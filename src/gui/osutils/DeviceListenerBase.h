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

#ifndef DEVICELISTENER_BASE_H
#define DEVICELISTENER_BASE_H

#include <QWidget>

class QUuid;
class QWidget;

/**
 * Base class for device listeners (USB and PC/SC).
 *
 * Provides a common interface for hotplug callback registration.
 */
class DeviceListenerBase : public QWidget
{
    Q_OBJECT

public:
    static constexpr int MATCH_ANY = -1;

    explicit DeviceListenerBase(QWidget* parent)
        : QWidget(parent)
    {
    }
    ~DeviceListenerBase() override = default;

    /**
     * Register a hotplug notification callback.
     *
     * Fires devicePlugged() when the state of a matching device changes.
     * The signals are supplied with the platform-specific context and ID of the firing device.
     * Registering a new callback with the same DeviceListener will unregister any previous callbacks.
     *
     * @param arrived listen for new devices
     * @param left listen for device unplug
     * @param vendorId vendor ID to listen for or DeviceListener::MATCH_ANY
     * @param productId product ID to listen for or DeviceListener::MATCH_ANY
     * @param deviceClass device class GUID (Windows only)
     */
    virtual void registerHotplugCallback(bool arrived,
                                         bool left,
                                         int vendorId = MATCH_ANY,
                                         int productId = MATCH_ANY,
                                         const QUuid* deviceClass = nullptr) = 0;

    virtual void deregisterAllHotplugCallbacks() = 0;

signals:
    void devicePlugged(bool state, void* ctx, void* device);
};

#endif // DEVICELISTENER_BASE_H
