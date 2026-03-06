/*
 * Copyright (C) 2023 KeePassXC Team <team@keepassxc.org>
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

#include "DeviceListener.h"

#if defined(Q_OS_WIN)
#include "winutils/DeviceListenerWin.h"
#elif defined(Q_OS_MACOS)
#include "macutils/DeviceListenerMac.h"
#elif defined(Q_OS_UNIX)
#include "nixutils/DeviceListenerLibUsb.h"
#endif

#include <QTimer>

DeviceListener::DeviceListener(QWidget* parent)
    : DeviceListenerBase(parent)
{

#if defined(Q_OS_MACOS)
    auto* usbListener = new DeviceListenerMac(this);
#elif defined(Q_OS_WIN)
    auto* usbListener = new DeviceListenerWin(this);
#elif defined(Q_OS_UNIX)
    auto* usbListener = new DeviceListenerLibUsb(this);
#endif
    m_listeners.append(usbListener);
    connectSignals(usbListener);
}

DeviceListener::~DeviceListener()
{
}

void DeviceListener::connectSignals(DeviceListenerBase* listener)
{
    connect(listener, &DeviceListenerBase::devicePlugged, this, [this](bool state, void* ctx, void* device) {
        // Wait a few ms to prevent USB device access conflicts
        QTimer::singleShot(50, this, [this, state, ctx, device] { emit devicePlugged(state, ctx, device); });
    });
}

void DeviceListener::registerHotplugCallback(bool arrived,
                                             bool left,
                                             int vendorId,
                                             int productId,
                                             const QUuid* deviceClass)
{
    for (auto& listener : m_listeners) {
        if (listener) {
            listener->registerHotplugCallback(arrived, left, vendorId, productId, deviceClass);
        }
    }
}

void DeviceListener::deregisterAllHotplugCallbacks()
{
    for (auto& listener : m_listeners) {
        if (listener) {
            listener->deregisterAllHotplugCallbacks();
        }
    }
}
