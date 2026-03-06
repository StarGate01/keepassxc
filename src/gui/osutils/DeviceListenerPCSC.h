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

#ifndef DEVICELISTENER_PCSC_H
#define DEVICELISTENER_PCSC_H

#include "DeviceListenerBase.h"
#include "PCSCUtils.h"

#include <QAtomicInt>
#include <QFuture>

/**
 * Cross-platform PC/SC smartcard reader and card state monitor.
 *
 * Monitors for:
 * - Reader addition/removal (via PnP notification on Windows/Linux, polling on macOS)
 * - Card insertion/removal on known readers
 *
 * Emits devicePlugged() when any state change is detected, triggering a rescan
 * of available hardware keys.
 */
class DeviceListenerPCSC : public DeviceListenerBase
{
    Q_OBJECT

public:
    explicit DeviceListenerPCSC(QWidget* parent);
    DeviceListenerPCSC(const DeviceListenerPCSC&) = delete;
    ~DeviceListenerPCSC() override;

    /**
     * Register for hotplug notifications.
     *
     * Starts monitoring if not already running. The vendor/product ID parameters
     * are ignored for PC/SC as we monitor all readers.
     */
    void registerHotplugCallback(bool arrived,
                                 bool left,
                                 int vendorId = MATCH_ANY,
                                 int productId = MATCH_ANY,
                                 const QUuid* deviceClass = nullptr) override;

    void deregisterAllHotplugCallbacks() override;

private:
    void monitorLoop();

    SCARDCONTEXT m_context{};
    QFuture<void> m_future;
    QAtomicInt m_running{0};
    QAtomicInt m_refCount{0};
};

#endif // DEVICELISTENER_PCSC_H
