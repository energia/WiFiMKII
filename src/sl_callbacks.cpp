#include "sl_callbacks.h"

#include "WiFiMKII.h"
#include <Energia.h>


#include "ti/drivers/net/wifi/wlan.h"
#include "ti/drivers/net/wifi/simplelink.h"

//*****************************************************************************
// SimpleLink Callback Functions
//*****************************************************************************

void SimpleLinkNetAppRequestMemFreeEventHandler (uint8_t *buffer)
{
  // do nothing...
}

void SimpleLinkNetAppRequestEventHandler (SlNetAppRequest_t *pNetAppRequest, SlNetAppResponse_t *pNetAppResponse)
{
  // do nothing...
}

//*****************************************************************************
//
//! \brief The Function Handles WLAN Events
//!
//! \param[in]  pWlanEvent - Pointer to WLAN Event Info
//!
//! \return None
//!
//*****************************************************************************
void SimpleLinkWlanEventHandler(SlWlanEvent_t *pWlanEvent)
{
    unsigned char tmp[4] = {0,0,0,0};

    switch (pWlanEvent->Id) {
        //
        //Wlan has connected to a station
        //brackets necessary to avoid crosses initialization error
        //
        case SL_WLAN_EVENT_CONNECT: {
            WiFiClass::WiFi_status = WL_CONNECTED;
            //
            //copy ssid name to WiFiClass and manually add null terminator
            //
            char* pSSID = (char*)pWlanEvent->Data.Connect.SsidName;
            uint8_t ssidLength = pWlanEvent->Data.Connect.SsidLen;
            if (ssidLength > MAX_SSID_LEN) {
                return;
            }
            memcpy(WiFiClass::connected_ssid, pSSID, ssidLength);
            WiFiClass::connected_ssid[ssidLength] = '\0';

            //
            //copy bssid to WiFiClass (no null terminator. Length always = 6)
            //
            char* pBSSID = (char*)pWlanEvent->Data.Connect.Bssid;
            WiFiClass::connected_bssid[5] = pBSSID[0];
            WiFiClass::connected_bssid[4] = pBSSID[1];
            WiFiClass::connected_bssid[3] = pBSSID[2];
            WiFiClass::connected_bssid[2] = pBSSID[3];
            WiFiClass::connected_bssid[1] = pBSSID[4];
            WiFiClass::connected_bssid[0] = pBSSID[5];
            break;
        }

        //
        //Wlan has disconnected, so completely zero out the ssid and bssid
        //
        case SL_WLAN_EVENT_DISCONNECT:
            WiFiClass::WiFi_status = WL_DISCONNECTED;
            memset(WiFiClass::connected_ssid, 0, MAX_SSID_LEN);
            memset(WiFiClass::connected_bssid, 0, BSSID_LEN);
            break;

        /* Track station connects & disconnects in AP mode */
        case SL_WLAN_EVENT_STA_ADDED:
            /* Register the MAC w/o an IP; later on, when an IP is leased to this user, the _latestConnect index will update
             * to point to this one (inside sl_NetAppEvtHdlr's run of _registerNewDeviceIP() below).
             */
            WiFiClass::_registerNewDeviceIP(tmp, pWlanEvent->Data.STAAdded.Mac);
            break;

        case SL_WLAN_EVENT_STA_REMOVED:
            WiFiClass::_unregisterDevice(pWlanEvent->Data.STARemoved.Mac);
            WiFiClass::_connectedDeviceCount--;
            break;
        default:
            break;
    }
}

//*****************************************************************************
//
//! \brief The Function Handles the Fatal errors
//!
//! \param[in]  slFatalErrorEvent - Pointer to Fatal Error Event info
//!
//! \return None
//!
//*****************************************************************************
void SimpleLinkFatalErrorEventHandler(SlDeviceFatal_t *slFatalErrorEvent)
{
#if 0
    switch (slFatalErrorEvent->Id)
    {
        case SL_DEVICE_EVENT_FATAL_DEVICE_ABORT:
        {
//            UART_PRINT("[ERROR] - FATAL ERROR: Abort NWP event detected: AbortType=%d, AbortData=0x%x\n\r",slFatalErrorEvent->Data.DeviceAssert.Code,slFatalErrorEvent->Data.DeviceAssert.Value);
        }
        break;

        case SL_DEVICE_EVENT_FATAL_DRIVER_ABORT:
        {
//            UART_PRINT("[ERROR] - FATAL ERROR: Driver Abort detected. \n\r");
        }
        break;

        case SL_DEVICE_EVENT_FATAL_NO_CMD_ACK:
        {
//            UART_PRINT("[ERROR] - FATAL ERROR: No Cmd Ack detected [cmd opcode = 0x%x] \n\r", slFatalErrorEvent->Data.NoCmdAck.Code);
        }
        break;

        case SL_DEVICE_EVENT_FATAL_SYNC_LOSS:
        {
//            UART_PRINT("[ERROR] - FATAL ERROR: Sync loss detected n\r");
        }
        break;

        case SL_DEVICE_EVENT_FATAL_CMD_TIMEOUT:
        {
//            UART_PRINT("[ERROR] - FATAL ERROR: Async event timeout detected [event opcode =0x%x]  \n\r", slFatalErrorEvent->Data.CmdTimeout.Code);
        }
        break;

        default:
//            UART_PRINT("[ERROR] - FATAL ERROR: Unspecified error detected \n\r");
        break;
    }
#endif
}

//*****************************************************************************
//
//! \brief This function handles network events such as IP acquisition, IP
//!           leased, IP released etc.
//!
//! \param[in]  pNetAppEvent - Pointer to NetApp Event Info 
//!
//! \return None
//!
//*****************************************************************************
void SimpleLinkNetAppEventHandler(SlNetAppEvent_t *pNetAppEvent)
{
#if 0
    switch (pSlSockEvent->Event) {
        //
        //IP address acquired. Copy the uint32 to the WiFiClass static variable
        //do the following for both IPV4 and IPV6
        //
        case SL_NETAPP_IPV4_IPACQUIRED_EVENT:
        case SL_NETAPP_IPV6_IPACQUIRED_EVENT:
        {
            WiFiClass::local_IP = pSlSockEvent->EventData.ipAcquiredV4.ip;
            break;
        }

        /* Track station IP leases in AP mode */
        case SL_NETAPP_IP_LEASED_EVENT:
            unsigned char ipAddrAry[4];

            ipAddrAry[0] = (pSlSockEvent->EventData.ipLeased.ip_address >> 24);
            ipAddrAry[1] = (pSlSockEvent->EventData.ipLeased.ip_address >> 16) & 0xFF;
            ipAddrAry[2] = (pSlSockEvent->EventData.ipLeased.ip_address >> 8) & 0xFF;
            ipAddrAry[3] = pSlSockEvent->EventData.ipLeased.ip_address & 0xFF;
            WiFiClass::_registerNewDeviceIP(ipAddrAry, pSlSockEvent->EventData.ipLeased.mac);
            WiFiClass::_connectedDeviceCount++;
            break;

        default:
            break;
    }
#endif
}

//*****************************************************************************
//
//! \brief This function handles HTTP server events
//!
//! \param[in]  pServerEvent - Contains the relevant event information
//! \param[in]    pServerResponse - Should be filled by the user with the
//!                                      relevant response information
//!
//! \return None
//!
//****************************************************************************
void SimpleLinkHttpServerEventHandler(SlNetAppHttpServerEvent_t *pHttpEvent,
                                    SlNetAppHttpServerResponse_t *pHttpResponse)
{
    // Unused in this application
}

//*****************************************************************************
//
//! \brief This function handles General Events
//!
//! \param[in]     pDevEvent - Pointer to General Event Info 
//!
//! \return None
//!
//*****************************************************************************
void SimpleLinkGeneralEventHandler(SlDeviceEvent_t *pDevEvent)
{
    // Unused in this application
}

//*****************************************************************************
//
//! This function handles socket events indication
//!
//! \param[in]      pSock - Pointer to Socket Event Info
//!
//! \return None
//!
//*****************************************************************************
void SimpleLinkSockEventHandler(SlSockEvent_t *pSock)
{

}

void SimpleLinkSocketTriggerEventHandler(SlSockTriggerEvent_t *pSlTriggerEvent)
{
}


