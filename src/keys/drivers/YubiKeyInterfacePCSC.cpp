/*
 *  Copyright (C) 2021 KeePassXC Team <team@keepassxc.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "YubiKeyInterfacePCSC.h"

#include "core/Tools.h"
#include "crypto/Random.h"
#include "gui/osutils/PCSCUtils.h"

#include <QScopeGuard>

// This namespace contains YubiKey-specific PC/SC APDU wrappers
namespace
{
    /***
     * @brief Finds the AID a card uses by checking a list of AIDs
     *
     * @param handle Smartcard handle
     * @param aid Application identifier byte string
     * @param result Smartcard handle and AID bytestring pair that will be populated on success
     *
     * @return true on success
     */
    bool findAID(SCARDHANDLE handle, const QList<QByteArray>& aid_codes, SCardAID& result)
    {
        for (const auto& aid : aid_codes) {
            // Ensure the transmission is retransmitted after card resets
            auto rv = PCSCUtils::transactRetry(handle, [&handle, &aid]() {
                // Try to select the card using the specified AID
                return PCSCUtils::selectApplet({handle, aid});
            });
            if (rv == SCARD_S_SUCCESS) {
                result.first = handle;
                result.second = aid;
                return true;
            }
        }
        return false;
    }

    /***
     * @brief Reads the serial number of a key
     *
     * @param handle Smartcard handle and applet ID bytestring pair
     * @param serial The serial number
     *
     * @return SCARD_S_SUCCESS on success
     */
    RETVAL getSerial(const SCardAID& handle, unsigned int& serial)
    {
        // Ensure the transmission is retransmitted after card resets
        return PCSCUtils::transactRetry(handle.first, [&handle, &serial]() {
            // Ensure that the card is always selected before sending the command
            auto rv = PCSCUtils::selectApplet(handle);
            if (rv != SCARD_S_SUCCESS) {
                return rv;
            }

            uint8_t pbSendBuffer[5] = {CLA_ISO, INS_API_REQ, CMD_GET_SERIAL, 0, 6};
            uint8_t pbRecvBuffer[6] = {0}; // 4 bytes serial, 2 bytes status
            SCUINT dwRecvLength = 6;

            rv = PCSCUtils::transmit(handle.first, pbSendBuffer, 5, pbRecvBuffer, dwRecvLength);
            if (rv == SCARD_S_SUCCESS && dwRecvLength >= 4) {
                // The serial number is encoded MSB first
                serial = (pbRecvBuffer[0] << 24) + (pbRecvBuffer[1] << 16) + (pbRecvBuffer[2] << 8) + (pbRecvBuffer[3]);
            }

            return rv;
        });
    }

    /***
     * @brief Creates a smartcard handle and applet select bytestring pair by looking up a serial key
     *
     * @param target_serial The serial number to search for
     * @param context A pre-established smartcard API context
     * @param aid_codes A list which contains the AIDs to scan for
     * @param handle The created smartcard handle and applet select bytestring pair
     *
     * @return SCARD_S_SUCCESS on success
     */
    RETVAL openKeySerial(const unsigned int target_serial,
                         SCARDCONTEXT& context,
                         const QList<QByteArray>& aid_codes,
                         SCardAID* handle)
    {
        // Ensure the Smartcard API handle is still valid
        auto rv = PCSCUtils::ensureValidContext(context);
        if (rv != SCARD_S_SUCCESS) {
            return rv;
        }

        auto readers_list = PCSCUtils::getReaders(context);

        // Iterate all connected readers
        foreach (const QString& reader_name, readers_list) {
            SCARDHANDLE hCard;
            SCUINT dwActiveProtocol = SCARD_PROTOCOL_UNDEFINED;
            rv = SCardConnect(context,
                              reader_name.toStdString().c_str(),
                              SCARD_SHARE_SHARED,
                              SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                              &hCard,
                              &dwActiveProtocol);

            if (rv == SCARD_S_SUCCESS) {
                // Read the ATR record of the card
                char pbReader[MAX_READERNAME] = {0};
                SCUINT dwReaderLen = sizeof(pbReader);
                SCUINT dwState = 0;
                SCUINT dwProt = SCARD_PROTOCOL_UNDEFINED;
                uint8_t pbAtr[MAX_ATR_SIZE] = {0};
                SCUINT dwAtrLen = sizeof(pbAtr);

                rv = SCardStatus(hCard, pbReader, &dwReaderLen, &dwState, &dwProt, pbAtr, &dwAtrLen);
                if (rv == SCARD_S_SUCCESS && (dwProt == SCARD_PROTOCOL_T0 || dwProt == SCARD_PROTOCOL_T1)) {
                    // Find which AID to use
                    SCardAID satr;
                    if (findAID(hCard, aid_codes, satr)) {
                        unsigned int serial = 0;
                        // Read the serial number of the card
                        getSerial(satr, serial);
                        if (serial == target_serial) {
                            handle->first = satr.first;
                            handle->second = satr.second;
                            return SCARD_S_SUCCESS;
                        }
                    }
                }

                SCardDisconnect(hCard, SCARD_LEAVE_CARD);
            }
        }

        return SCARD_E_NO_SMARTCARD;
    }

    /***
     * @brief Performs a challenge-response transmission
     *
     * The card computes the SHA1-HMAC  of the challenge
     * using its pre-programmed secret key and return the response
     *
     * @param handle Smartcard handle and applet ID bytestring pair
     * @param slot_cmd Either CMD_HMAC_1 for slot 1 or CMD_HMAC_2 for slot 2
     * @param input Challenge byte buffer, exactly 64 bytes and padded using PKCS#7 or Yubikey padding
     * @param output Response byte buffer, exactly 20 bytes
     *
     * @return SCARD_S_SUCCESS on success
     */
    RETVAL getHMAC(const SCardAID& handle, uint8_t slot_cmd, const uint8_t input[64], uint8_t output[20])
    {
        // Ensure the transmission is retransmitted after card resets
        return PCSCUtils::transactRetry(handle.first, [&handle, &slot_cmd, &input, &output]() {
            auto rv = PCSCUtils::selectApplet(handle);

            // Ensure that the card is always selected before sending the command
            if (rv != SCARD_S_SUCCESS) {
                return rv;
            }

            uint8_t pbSendBuffer[5 + 64] = {CLA_ISO, INS_API_REQ, slot_cmd, 0, 64};
            memcpy(pbSendBuffer + 5, input, 64);
            uint8_t pbRecvBuffer[22] = {0}; // 20 bytes hmac, 2 bytes status
            SCUINT dwRecvLength = 22;

            rv = PCSCUtils::transmit(handle.first, pbSendBuffer, 5 + 64, pbRecvBuffer, dwRecvLength);
            if (rv == SCARD_S_SUCCESS && dwRecvLength >= 20) {
                memcpy(output, pbRecvBuffer, 20);
            }

            // If transmission is successful but no data is returned
            // then the slot is probably not configured for HMAC-SHA1
            // but for OTP or nothing instead
            if (rv == SCARD_S_SUCCESS && dwRecvLength != 22) {
                return SCARD_E_FILE_NOT_FOUND;
            }

            return rv;
        });
    }
} // namespace

YubiKeyInterfacePCSC::YubiKeyInterfacePCSC()
    : YubiKeyInterface()
{
    if (PCSCUtils::ensureValidContext(m_sc_context) != SCARD_S_SUCCESS) {
        qDebug("YubiKey: Failed to establish PC/SC context.");
    } else {
        m_initialized = true;
    }
}

YubiKeyInterfacePCSC::~YubiKeyInterfacePCSC()
{
    if (m_initialized && SCardReleaseContext(m_sc_context) != SCARD_S_SUCCESS) {
        qDebug("YubiKey: Failed to release PC/SC context.");
    }
}

YubiKeyInterfacePCSC* YubiKeyInterfacePCSC::m_instance(nullptr);

YubiKeyInterfacePCSC* YubiKeyInterfacePCSC::instance()
{
    if (!m_instance) {
        m_instance = new YubiKeyInterfacePCSC();
    }

    return m_instance;
}

YubiKey::KeyMap YubiKeyInterfacePCSC::findValidKeys(int& connectedKeys)
{
    m_error.clear();
    if (!isInitialized()) {
        return {};
    }

    YubiKey::KeyMap foundKeys;

    // Connect to each reader and look for cards
    for (const auto& reader_name : PCSCUtils::getReaders(m_sc_context)) {
        /* Some Yubikeys present their PCSC interface via USB as well
           Although this would not be a problem in itself,
           we filter these connections because in USB mode,
           the PCSC challenge-response interface is usually locked
           Instead, the other USB (HID) interface should pick up and
           interface the key.
           For more info see the comment block further below. */
        if (reader_name.contains("yubikey", Qt::CaseInsensitive)) {
            continue;
        }

        SCARDHANDLE hCard;
        SCUINT dwActiveProtocol = SCARD_PROTOCOL_UNDEFINED;
        auto rv = SCardConnect(m_sc_context,
                               reader_name.toStdString().c_str(),
                               SCARD_SHARE_SHARED,
                               SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                               &hCard,
                               &dwActiveProtocol);

        if (rv != SCARD_S_SUCCESS) {
            // Cannot connect to the reader
            continue;
        }

        auto finally = qScopeGuard([hCard]() { SCardDisconnect(hCard, SCARD_LEAVE_CARD); });

        // Read the protocol and the ATR record
        char pbReader[MAX_READERNAME] = {0};
        SCUINT dwReaderLen = sizeof(pbReader);
        SCUINT dwState = 0;
        SCUINT dwProt = SCARD_PROTOCOL_UNDEFINED;
        uint8_t pbAtr[MAX_ATR_SIZE] = {0};
        SCUINT dwAtrLen = sizeof(pbAtr);

        rv = SCardStatus(hCard, pbReader, &dwReaderLen, &dwState, &dwProt, pbAtr, &dwAtrLen);
        if (rv != SCARD_S_SUCCESS || (dwProt != SCARD_PROTOCOL_T0 && dwProt != SCARD_PROTOCOL_T1)) {
            // Could not read the ATR record or the protocol is not supported
            continue;
        }

        // Find which AID to use
        SCardAID satr;
        if (findAID(hCard, m_aid_codes, satr)) {
            // Build the UI name using the display name found in the ATR map
            QByteArray atr(reinterpret_cast<char*>(pbAtr), dwAtrLen);
            QString name("Unknown Key");
            if (m_atr_names.contains(atr)) {
                name = m_atr_names.value(atr);
            }

            unsigned int serial = 0;
            getSerial(satr, serial);

            ++connectedKeys;

            /* This variable indicates that the key is locked / timed out.
                When using the key via NFC, the user has to re-present the key to clear the timeout.
                Also, the key can be programmatically reset (see below).
                When using the key via USB (where the Yubikey presents as a PCSC reader in itself),
                the non-HMAC-SHA1 slots (eg. OTP) are incorrectly recognized as locked HMAC-SHA1 slots.
                Due to this conundrum, we exclude "locked" keys from the key enumeration,
                but only if the reader is the "virtual yubikey reader device".
                This also has the nice side effect of de-duplicating interfaces when a key
                Is connected via USB and also accessible via PCSC */
            bool wouldBlock = false;
            /* When the key is used via NFC, the lock state / time-out is cleared when
                the smartcard connection is re-established / the applet is selected
                so the next call to performTestChallenge actually clears the lock.
                Due to this the key is unlocked, and we display it as such.
                When the key times out in the time between the key listing and
                the database unlock /save, an interaction request will be displayed. */
            for (int slot = 1; slot <= 2; ++slot) {
                if (performTestChallenge(&satr, slot, &wouldBlock)) {
                    auto display =
                        tr("(NFC) %1 [%2] - Slot %3, %4", "YubiKey display fields")
                            .arg(name,
                                 QString::number(serial),
                                 QString::number(slot),
                                 wouldBlock ? tr("Press", "USB Challenge-Response Key interaction request")
                                            : tr("Passive", "USB Challenge-Response Key no interaction required"));
                    foundKeys.insert({serial, slot}, display);
                }
            }
        }
    }

    return foundKeys;
}

bool YubiKeyInterfacePCSC::testChallenge(YubiKeySlot slot, bool* wouldBlock)
{
    bool ret = false;
    SCardAID hCard;

    auto rv = openKeySerial(slot.first, m_sc_context, m_aid_codes, &hCard);
    if (rv == SCARD_S_SUCCESS) {
        ret = performTestChallenge(&hCard, slot.second, wouldBlock);
        SCardDisconnect(hCard.first, SCARD_LEAVE_CARD);
    }

    return ret;
}

bool YubiKeyInterfacePCSC::performTestChallenge(void* key, int slot, bool* wouldBlock)
{
    // Array has to be at least one byte or else the yubikey would interpret everything as padding
    auto chall = randomGen()->randomArray(1);
    Botan::secure_vector<char> resp;
    auto ret = performChallenge(static_cast<SCardAID*>(key), slot, false, chall, resp);
    if (ret == YubiKey::ChallengeResult::YCR_SUCCESS || ret == YubiKey::ChallengeResult::YCR_WOULDBLOCK) {
        if (wouldBlock) {
            *wouldBlock = ret == YubiKey::ChallengeResult::YCR_WOULDBLOCK;
        }
        return true;
    }
    return false;
}

YubiKey::ChallengeResult
YubiKeyInterfacePCSC::challenge(YubiKeySlot slot, const QByteArray& challenge, Botan::secure_vector<char>& response)
{
    m_error.clear();
    if (!m_initialized) {
        m_error = tr("The YubiKey PC/SC interface has not been initialized.");
        return YubiKey::ChallengeResult::YCR_KEYNOTFOUND;
    }

    // Try for a few seconds to find the key
    emit challengeStarted();

    SCardAID hCard;
    int tries = 20; // 5 seconds, test every 250 ms
    while (tries > 0) {
        auto rv = openKeySerial(slot.first, m_sc_context, m_aid_codes, &hCard);
        // Key with specified serial number is found
        if (rv == SCARD_S_SUCCESS) {
            auto ret = performChallenge(&hCard, slot.second, true, challenge, response);
            SCardDisconnect(hCard.first, SCARD_LEAVE_CARD);

            /* If this would be YCR_WOULDBLOCK, the key is locked.
               So we wait for the user to re-present it to clear the time-out
               This condition usually only happens when the key times out after
               the initial key listing, because performTestChallenge implicitly
               resets the key (see comment above) */
            if (ret == YubiKey::ChallengeResult::YCR_SUCCESS) {
                emit challengeCompleted();
                return ret;
            }
        }

        if (--tries > 0) {
            Tools::sleep(250);
        }
    }

    emit challengeCompleted();
    return YubiKey::ChallengeResult::YCR_KEYNOTFOUND;
}

YubiKey::ChallengeResult YubiKeyInterfacePCSC::performChallenge(void* key,
                                                                int slot,
                                                                bool mayBlock,
                                                                const QByteArray& challenge,
                                                                Botan::secure_vector<char>& response)
{
    // Always block (i.e. wait for the user to touch the key to the reader)
    Q_UNUSED(mayBlock);

    m_error.clear();
    int yk_cmd = (slot == 1) ? CMD_HMAC_1 : CMD_HMAC_2;
    QByteArray paddedChallenge = challenge;

    response.clear();
    response.resize(20);

    /*
     * The challenge sent to the Yubikey should always be 64 bytes for
     * compatibility with all configurations.  Follow PKCS7 padding.
     *
     * There is some question whether or not 64 bytes fixed length
     * configurations even work, some docs say avoid it.
     *
     * In fact, the Yubikey always assumes the last byte (nr. 64)
     * and all bytes of the same value preceding it to be padding.
     * This does not conform fully to PKCS7, because the the actual value
     * of the padding bytes is ignored.
     */
    const int padLen = 64 - paddedChallenge.size();
    if (padLen > 0) {
        paddedChallenge.append(QByteArray(padLen, padLen));
    }

    auto c = reinterpret_cast<const unsigned char*>(paddedChallenge.constData());
    auto r = reinterpret_cast<unsigned char*>(response.data());

    auto rv = getHMAC(*static_cast<SCardAID*>(key), yk_cmd, c, r);
    if (rv != SCARD_S_SUCCESS) {
        if (rv == SCARD_W_CARD_NOT_AUTHENTICATED) {
            m_error = tr("Hardware key is locked or timed out. Unlock or re-present it to continue.");
            return YubiKey::ChallengeResult::YCR_WOULDBLOCK;
        } else if (rv == SCARD_E_FILE_NOT_FOUND) {
            m_error = tr("Hardware key was not found or is not configured.");
        } else {
            m_error =
                tr("Failed to complete a challenge-response, the PC/SC error code was: %1").arg(QString::number(rv));
        }

        return YubiKey::ChallengeResult::YCR_ERROR;
    }

    return YubiKey::ChallengeResult::YCR_SUCCESS;
}
