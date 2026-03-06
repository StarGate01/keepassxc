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

#ifndef PCSCUTILS_H
#define PCSCUTILS_H

#include <QByteArray>
#include <QPair>
#include <QSet>
#include <QString>

#include <functional>
#include <winscard.h>

// MSYS2 does not define these macros
// Use values from pcsc-lite
#ifndef MAX_ATR_SIZE
#define MAX_ATR_SIZE 33
#endif
#ifndef MAX_READERNAME
#define MAX_READERNAME 128
#endif

// PC/SC framework on macOS uses unsigned int
// Windows winscard and Linux pcsc-lite use unsigned long
#ifdef Q_OS_MACOS
typedef uint32_t SCUINT;
typedef uint32_t RETVAL;
#else
typedef unsigned long SCUINT;
typedef long RETVAL;
#endif

// ISO 7816-4 APDU command constants
constexpr uint8_t CLA_ISO = 0x00;
constexpr uint8_t INS_SELECT = 0xA4;
constexpr uint8_t INS_GET_RESPONSE = 0xC0;
constexpr uint8_t SEL_APP_AID = 0x04;

// ISO 7816-4 status word constants
constexpr uint8_t SW_OK_HIGH = 0x90;
constexpr uint8_t SW_OK_LOW = 0x00;
constexpr uint8_t SW_MORE_DATA_HIGH = 0x61;
constexpr uint8_t SW_PRECOND_HIGH = 0x69;
constexpr uint8_t SW_PRECOND_LOW = 0x85;
constexpr uint8_t SW_NOTFOUND_HIGH = 0x6A;
constexpr uint8_t SW_NOTFOUND_LOW = 0x82;
constexpr uint8_t SW_UNSUP_HIGH = 0x6D;

// Smartcard handle paired with application identifier
typedef QPair<SCARDHANDLE, QByteArray> SCardAID;

namespace PCSCUtils
{
    /**
     * Establish or re-establish a valid PC/SC context.
     *
     * Handles context recovery after PC/SC daemon restarts or USB hot-unplug
     * events on Windows that can invalidate existing contexts.
     *
     * @param context Reference to context handle (will be modified)
     * @return SCARD_S_SUCCESS on success, error code otherwise
     */
    RETVAL ensureValidContext(SCARDCONTEXT& context);

    /**
     * Get set of connected smartcard reader names.
     *
     * @param context Valid PC/SC context
     * @return Set of reader names, empty on error
     */
    QSet<QString> getReaders(SCARDCONTEXT context);

    /**
     * Read the status and protocol of a smartcard handle.
     *
     * This function reads the OS API state without transmitting data.
     *
     * @param handle Smartcard handle
     * @param dwProt Output: protocol currently in use
     * @param pioSendPci Output: pointer to the PCI header for sending
     * @return SCARD_S_SUCCESS on success, error code otherwise
     */
    RETVAL getCardStatus(SCARDHANDLE handle, SCUINT& dwProt, const SCARD_IO_REQUEST*& pioSendPci);

    /**
     * Execute a transaction with automatic retry on card reset.
     *
     * A card not opened in exclusive mode can be reset by another process.
     * This function handles the reset acknowledgment and retransmission.
     *
     * @param handle Smartcard handle
     * @param action Lambda containing the transaction to execute
     * @return SCARD_S_SUCCESS on success, error code otherwise
     */
    RETVAL transactRetry(SCARDHANDLE handle, const std::function<RETVAL()>& action);

    /**
     * Transmit an APDU to the smartcard and read the response.
     *
     * Handles GET RESPONSE chaining for long responses and interprets
     * ISO 7816-4 status words, converting them to PC/SC error codes.
     *
     * @param handle Smartcard handle
     * @param sendBuffer Data to send
     * @param sendLength Length of data to send
     * @param recvBuffer Buffer for response data
     * @param recvLength In: buffer size, Out: received length
     * @return SCARD_S_SUCCESS on success, error code otherwise
     */
    RETVAL
    transmit(SCARDHANDLE handle, const uint8_t* sendBuffer, SCUINT sendLength, uint8_t* recvBuffer, SCUINT& recvLength);

    /**
     * Select an application on the smartcard by AID.
     *
     * Sends a standard ISO 7816-4 SELECT command.
     *
     * @param handle Smartcard handle and AID pair
     * @return SCARD_S_SUCCESS on success, error code otherwise
     */
    RETVAL selectApplet(const SCardAID& handle);

} // namespace PCSCUtils

#endif // PCSCUTILS_H
