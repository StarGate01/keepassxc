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

#include "PCSCUtils.h"

namespace PCSCUtils
{
    RETVAL ensureValidContext(SCARDCONTEXT& context)
    {
        // This check only tests if the handle pointer is valid in memory
        // but it does not actually verify that it works
        RETVAL rv = SCardIsValidContext(context);

        // If the handle is broken, create it
        // This happens e.g. on application launch
        if (rv != SCARD_S_SUCCESS) {
            rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, nullptr, nullptr, &context);
            if (rv != SCARD_S_SUCCESS) {
                return rv;
            }
        }

        // Verify the handle actually works by testing an API call
        SCUINT dwReaders = 0;
        rv = SCardListReaders(context, nullptr, nullptr, &dwReaders);

        // On Windows, USB hot-plugging can cause the PC/SC service to restart
        // On Linux, pcscd daemon restart invalidates existing contexts
        if (rv == SCARD_E_SERVICE_STOPPED || rv == SCARD_E_NO_SERVICE) {
            SCardReleaseContext(context);
            rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, nullptr, nullptr, &context);
        }

        return rv;
    }

    QSet<QString> getReaders(SCARDCONTEXT context)
    {
        QSet<QString> readers;
        SCUINT dwReaders = 0;

        // First call: get required buffer size
        // macOS does not support auto-allocate
        auto rv = SCardListReaders(context, nullptr, nullptr, &dwReaders);
        if (rv != SCARD_S_SUCCESS || dwReaders == 0 || dwReaders > 16384) {
            return readers;
        }

        // Second call: get actual reader names
        QByteArray buffer(static_cast<int>(dwReaders) + 2, '\0');
        rv = SCardListReaders(context, nullptr, buffer.data(), &dwReaders);
        if (rv != SCARD_S_SUCCESS) {
            return readers;
        }

        // Reader names are null-separated, list ends with double null
        const char* ptr = buffer.constData();
        while (*ptr != '\0') {
            QString name = QString::fromUtf8(ptr);
            readers.insert(name);
            ptr += name.size() + 1;
        }

        return readers;
    }

    RETVAL getCardStatus(SCARDHANDLE handle, SCUINT& dwProt, const SCARD_IO_REQUEST*& pioSendPci)
    {
        char pbReader[MAX_READERNAME] = {0};
        SCUINT dwReaderLen = sizeof(pbReader);
        SCUINT dwState = 0;
        uint8_t pbAtr[MAX_ATR_SIZE] = {0};
        SCUINT dwAtrLen = sizeof(pbAtr);

        auto rv = SCardStatus(handle, pbReader, &dwReaderLen, &dwState, &dwProt, pbAtr, &dwAtrLen);
        if (rv == SCARD_S_SUCCESS) {
            switch (dwProt) {
            case SCARD_PROTOCOL_T0:
                pioSendPci = SCARD_PCI_T0;
                break;
            case SCARD_PROTOCOL_T1:
                pioSendPci = SCARD_PCI_T1;
                break;
            default:
                rv = SCARD_E_PROTO_MISMATCH;
                break;
            }
        }

        return rv;
    }

    RETVAL transactRetry(SCARDHANDLE handle, const std::function<RETVAL()>& action)
    {
        SCUINT dwProt = SCARD_PROTOCOL_UNDEFINED;
        const SCARD_IO_REQUEST* pioSendPci = nullptr;
        auto rv = getCardStatus(handle, dwProt, pioSendPci);

        if (rv == SCARD_S_SUCCESS) {
            // Begin a transaction to lock out other processes
            rv = SCardBeginTransaction(handle);
            if (rv == SCARD_S_SUCCESS) {
                int retries;
                for (retries = 3; retries > 0; retries--) {
                    RETVAL actionResult = action();
                    if (actionResult == SCARD_W_RESET_CARD) {
                        // Card was reset during transmission, reconnect
                        SCUINT dwProtNew = SCARD_PROTOCOL_UNDEFINED;
                        rv = SCardReconnect(handle, SCARD_SHARE_SHARED, dwProt, SCARD_LEAVE_CARD, &dwProtNew);
#ifdef Q_OS_WIN
                        // On Windows, transaction must be restarted after reconnect
                        if (rv == SCARD_S_SUCCESS) {
                            rv = SCardBeginTransaction(handle);
                        }
#endif
                        qDebug("Smartcard was reset and had to be reconnected");
                    } else {
                        rv = actionResult;
                        break;
                    }
                }
                if (retries == 0) {
                    rv = SCARD_W_RESET_CARD;
                    qDebug("Smartcard was reset and failed to reconnect after 3 tries");
                }
            }
        }

        SCardEndTransaction(handle, SCARD_LEAVE_CARD);
        return rv;
    }

    RETVAL
    transmit(SCARDHANDLE handle, const uint8_t* sendBuffer, SCUINT sendLength, uint8_t* recvBuffer, SCUINT& recvLength)
    {
        SCUINT dwProt = SCARD_PROTOCOL_UNDEFINED;
        const SCARD_IO_REQUEST* pioSendPci = nullptr;
        auto rv = getCardStatus(handle, dwProt, pioSendPci);

        if (rv != SCARD_S_SUCCESS) {
            return rv;
        }

        const SCUINT recvBufferSize = recvLength;
        rv = SCardTransmit(handle, pioSendPci, sendBuffer, sendLength, nullptr, recvBuffer, &recvLength);

        if (recvLength < 2) {
            return SCARD_E_UNEXPECTED;
        }

        // Handle GET RESPONSE chaining for long responses
        uint8_t sw1 = recvBuffer[recvLength - 2];
        if (sw1 == SW_MORE_DATA_HIGH) {
            while (true) {
                if (recvBufferSize < recvLength) {
                    return SCARD_E_UNEXPECTED;
                }
                // Overwrite status word in buffer
                recvLength -= 2;
                SCUINT chunkLength = recvBufferSize - recvLength;
                const uint8_t requestSize = qBound(static_cast<SCUINT>(0), chunkLength - 2, static_cast<SCUINT>(255));
                uint8_t getResponseCmd[] = {CLA_ISO, INS_GET_RESPONSE, 0, 0, requestSize};

                rv = SCardTransmit(handle,
                                   pioSendPci,
                                   getResponseCmd,
                                   sizeof(getResponseCmd),
                                   nullptr,
                                   recvBuffer + recvLength,
                                   &chunkLength);

                if (!(rv == SCARD_S_SUCCESS && chunkLength >= 2)) {
                    break;
                }

                recvLength += chunkLength;
                sw1 = recvBuffer[recvLength - 2];
                if (sw1 != SW_MORE_DATA_HIGH) {
                    break;
                }
            }
        }

        if (rv != SCARD_S_SUCCESS) {
            return rv;
        }

        if (recvLength < 2) {
            return SCARD_E_UNEXPECTED;
        }

        // Interpret ISO 7816-4 status words
        const uint8_t swHigh = recvBuffer[recvLength - 2];
        const uint8_t swLow = recvBuffer[recvLength - 1];

        if (swHigh == SW_OK_HIGH && swLow == SW_OK_LOW) {
            return SCARD_S_SUCCESS;
        } else if (swHigh == SW_PRECOND_HIGH && swLow == SW_PRECOND_LOW) {
            return SCARD_W_CARD_NOT_AUTHENTICATED;
        } else if ((swHigh == SW_NOTFOUND_HIGH && swLow == SW_NOTFOUND_LOW) || swHigh == SW_UNSUP_HIGH) {
            return SCARD_E_FILE_NOT_FOUND;
        }

        return SCARD_E_UNEXPECTED;
    }

    RETVAL selectApplet(const SCardAID& handle)
    {
        uint8_t header[5] = {CLA_ISO, INS_SELECT, SEL_APP_AID, 0, static_cast<uint8_t>(handle.second.size())};
        QByteArray sendBuffer(reinterpret_cast<char*>(header), 5);
        sendBuffer.append(handle.second);

        uint8_t recvBuffer[64] = {0};
        SCUINT recvLength = sizeof(recvBuffer);

        return transmit(handle.first,
                        reinterpret_cast<const uint8_t*>(sendBuffer.constData()),
                        sendBuffer.size(),
                        recvBuffer,
                        recvLength);
    }

} // namespace PCSCUtils
