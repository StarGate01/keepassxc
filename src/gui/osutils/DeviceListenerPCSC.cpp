/*
 * Copyright (C) 2026 KeePassXC Team <team@keepassxc.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 or (at your option)
 * version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "DeviceListenerPCSC.h"
#include "PCSCUtils.h"

#include <QSet>
#include <QtConcurrent>

// Special reader name for PnP notifications (reader arrival/removal)
// Supported on Windows and Linux (pcsc-lite >= 1.6.0), NOT on macOS
static const char* PNP_READER_NAME = "\\\\?PnP?\\Notification";

DeviceListenerPCSC::DeviceListenerPCSC(QWidget* parent)
    : DeviceListenerBase(parent)
{
}

DeviceListenerPCSC::~DeviceListenerPCSC()
{
    deregisterAllHotplugCallbacks();
    SCardReleaseContext(m_context);
}

void DeviceListenerPCSC::registerHotplugCallback(bool arrived,
                                                 bool left,
                                                 int vendorId,
                                                 int productId,
                                                 const QUuid* deviceClass)
{
    Q_UNUSED(arrived)
    Q_UNUSED(left)
    Q_UNUSED(vendorId)
    Q_UNUSED(productId)
    Q_UNUSED(deviceClass)

    if (m_refCount.fetchAndAddRelaxed(1) == 0) {
        if (m_running.loadRelaxed()) {
            return;
        }
        m_running.storeRelaxed(1);
        m_future = QtConcurrent::run([this] { monitorLoop(); });
    }
}

void DeviceListenerPCSC::deregisterAllHotplugCallbacks()
{
    if (m_refCount.fetchAndStoreRelaxed(0) > 0) {
        if (!m_running.fetchAndStoreRelaxed(0)) {
            return;
        }
        SCardCancel(m_context);
        m_future.waitForFinished();
    }
}

void DeviceListenerPCSC::monitorLoop()
{
    // Track known readers for change detection
    QSet<QString> knownReaders;

    // Storage for reader names (must persist while SCARD_READERSTATE references them)
    QList<QByteArray> readerNameStorage;

    std::vector<SCARD_READERSTATE> states;

    while (m_running.loadRelaxed()) {
        // Ensure context is valid (handles daemon restarts, etc.)
        if (PCSCUtils::ensureValidContext(m_context) != SCARD_S_SUCCESS) {
            // Context invalid, wait a bit and retry
            QThread::msleep(1000);
            continue;
        }

        // Get current reader list
        QSet<QString> currentReaders = PCSCUtils::getReaders(m_context);

        // Check if reader list changed
        bool readersChanged = !(currentReaders - knownReaders).empty();
        if (readersChanged) {
            knownReaders = currentReaders;

            readerNameStorage.clear();
            readerNameStorage.append(PNP_READER_NAME);
            states.clear();
            for (const auto& name : knownReaders) {
                auto uname = name.toUtf8();
                readerNameStorage.append(uname);
                SCARD_READERSTATE state = {};
                state.szReader = uname.constData();
                state.dwCurrentState = SCARD_STATE_UNAWARE;
                states.push_back(state);
            }

            // Emit signal to trigger key rescan
            emit devicePlugged(true, nullptr, nullptr);
        }

        // Wait for state change with timeout
        // Timeout ensures periodic reader list refresh (important for macOS)
        DWORD timeout = 2000; // 2 seconds
        auto rv = SCardGetStatusChange(m_context, timeout, states.data(), static_cast<DWORD>(states.size()));

        // Update current states for next iteration
        if (rv == SCARD_S_SUCCESS || rv == static_cast<RETVAL>(SCARD_E_TIMEOUT)) {

            // Check for meaningful state changes
            bool stateChanged = false;
            for (size_t i = 0; i < states.size(); ++i) {
                auto& s = states[i];
                s.dwCurrentState = s.dwEventState;

                // Skip unknown readers (PnP on macOS)
                if (s.dwEventState & SCARD_STATE_UNKNOWN) {
                    continue;
                }

                if (s.dwEventState & SCARD_STATE_CHANGED) {
                    stateChanged = true;
                    break;
                }
            }

            if (stateChanged && rv == SCARD_S_SUCCESS) {
                emit devicePlugged(true, nullptr, nullptr);
            }
        }

        // Handle context invalidation
        if (rv == SCARD_E_SERVICE_STOPPED || rv == SCARD_E_NO_SERVICE || rv == SCARD_E_INVALID_HANDLE
            || rv == SCARD_E_UNKNOWN_READER) {
            // Reset states for next iteration
            knownReaders.clear();
            readerNameStorage.clear();
            QThread::msleep(500);
        }

        // Handle cancellation (from stop())
        if (rv == SCARD_E_CANCELLED) {
            break;
        }
    }
}
