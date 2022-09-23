/*
 *  Copyright (c) 2016, The OpenThread Authors.
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. Neither the name of the copyright holder nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

#include <assert.h>
#include <openthread-core-config.h>
#include <openthread/config.h>

#include <openthread/cli.h>
#include <openthread/diag.h>
#include <openthread/tasklet.h>
#include <openthread/platform/logging.h>

#include <string.h>
#include <openthread/ip6.h>
#include <openthread/thread.h>
#include <openthread/dataset.h>
#include <openthread/udp.h>
#include <openthread/message.h>

#include "openthread-system.h"
#include "cli/cli_config.h"
#include "common/code_utils.hpp"

#include "lib/platform/reset_util.h"

struct otUdpSocket mSocket;
struct otOperationalDataset dataset_;
static const uint16_t PAN_ID = 0x4321;
static const uint16_t udpSocketPort = 0x2345;
static const bool udpSender = false;
static const size_t maxTicks = 50000;

const char *ipv6String[4] = {
                                "fdd0:e2e6:ee95:3757:c593:567a:6e14:ecaf",
                                "fdd0:e2e6:ee95:3757:27f:ea15:17b7:8582",
                                "fdd0:e2e6:ee95:3757:63b0:b693:d14d:355f",
                                "fdd0:e2e6:ee95:3757:9893:d993:3843:6292"
                            };

/**
 * This function initializes the CLI app.
 *
 * @param[in]  aInstance  The OpenThread instance structure.
 *
 */
extern void otAppCliInit(otInstance *aInstance);

#if OPENTHREAD_CONFIG_HEAP_EXTERNAL_ENABLE
void *otPlatCAlloc(size_t aNum, size_t aSize)
{
    return calloc(aNum, aSize);
}

void otPlatFree(void *aPtr)
{
    free(aPtr);
}
#endif

void otTaskletsSignalPending(otInstance *aInstance)
{
    OT_UNUSED_VARIABLE(aInstance);
}

#if OPENTHREAD_POSIX && !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
static otError ProcessExit(void *aContext, uint8_t aArgsLength, char *aArgs[])
{
    OT_UNUSED_VARIABLE(aContext);
    OT_UNUSED_VARIABLE(aArgsLength);
    OT_UNUSED_VARIABLE(aArgs);

    exit(EXIT_SUCCESS);
}

#if OPENTHREAD_EXAMPLES_SIMULATION
extern otError ProcessNodeIdFilter(void *aContext, uint8_t aArgsLength, char *aArgs[]);
#endif

static const otCliCommand kCommands[] = {
    {"exit", ProcessExit},
#if OPENTHREAD_EXAMPLES_SIMULATION
    {"nodeidfilter", ProcessNodeIdFilter},
#endif
};
#endif // OPENTHREAD_POSIX && !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)

static void setPanId(const uint16_t panId)
{
    dataset_.mPanId = panId;
    dataset_.mComponents.mIsPanIdPresent = true;
}

static void setChannel(const uint8_t channel)
{
    dataset_.mChannel = channel;
    dataset_.mComponents.mIsChannelPresent = true;
}

static int setNetworkKey(const uint8_t *networkKey)
{
    if (networkKey == NULL)
    {
        return -1;
    }

    memcpy(dataset_.mNetworkKey.m8, networkKey, sizeof(dataset_.mNetworkKey.m8));
    dataset_.mComponents.mIsNetworkKeyPresent = true;

    return 0;
}

static int setNetworkName(const char *networkName)
{
    if (networkName == NULL)
    {
        return -1;
    }

    if (otNetworkNameFromString(&dataset_.mNetworkName, networkName) == OT_ERROR_NONE)
    {
        dataset_.mComponents.mIsNetworkNamePresent = true;
        return 0;
    }

    return -1;
}

void initCustomValues(otInstance *instance)
{
    otError err = OT_ERROR_NONE;

    if (otDatasetIsCommissioned(instance))
    {
        err = otDatasetGetActive(instance, &dataset_);
        otDatasetSetPending(instance, &dataset_);
    }
    else
    {
        err = otDatasetGetPending(instance, &dataset_);
    }

    const char *networkName = "OpenThread-Fourtress";
    const uint8_t networkKey[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                   0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    const uint8_t channel = 15;

    setChannel(channel);
    setNetworkName(networkName);
    setNetworkKey(networkKey);
    setPanId(PAN_ID);

    otDatasetSetActive(instance, &dataset_);
}

static void HandleUdpReceive(void *aContext, otMessage *aMessage, const otMessageInfo *aMessageInfo)
{
    char buf[1500];
    int  length;

    length      = otMessageRead(aMessage, otMessageGetOffset(aMessage), buf, sizeof(buf) - 1);
    buf[length] = '\0';

    otCliOutputFormat("\n\r%d bytes from port 0x%04X: %s", length, aMessageInfo->mPeerPort, buf);
}

static void openUdp(otInstance *instance)
{
    memset(&mSocket, 0, sizeof(mSocket));

    if (!otUdpIsOpen(instance, &mSocket))
    {
        otError error = otUdpOpen(instance, &mSocket, HandleUdpReceive, NULL);
    }
}

static void bindUdp(otInstance *instance)
{
    otSockAddr sockaddr;
    sockaddr.mPort = udpSocketPort;
    otIp6AddressFromString("::", &sockaddr.mAddress);

    otError error = otUdpBind(instance, &mSocket, &sockaddr, OT_NETIF_THREAD);
}

static void sendUdp(otInstance* instance)
{
    const char *string = "hello world";
    otMessage *       message = NULL;
    otMessageInfo     messageInfo;
    otMessageSettings messageSettings = {true, OT_MESSAGE_PRIORITY_NORMAL};

    memset(&messageInfo, 0, sizeof(messageInfo));

    otIp6AddressFromString(ipv6String[0], &messageInfo.mPeerAddr);
    messageInfo.mPeerPort = udpSocketPort;

    message = otUdpNewMessage(instance, &messageSettings);
    otMessageAppend(message, string, strlen(string));

    otUdpSend(instance, &mSocket, message, &messageInfo);
    message = NULL;
    otCliOutputFormat("Sending udp message\r\n");
}

int main(int argc, char *argv[])
{
    otInstance *instance;

    OT_SETUP_RESET_JUMP(argv);

#if OPENTHREAD_CONFIG_MULTIPLE_INSTANCE_ENABLE
    size_t   otInstanceBufferLength = 0;
    uint8_t *otInstanceBuffer       = NULL;
#endif

pseudo_reset:

    otSysInit(argc, argv);

#if OPENTHREAD_CONFIG_MULTIPLE_INSTANCE_ENABLE
    // Call to query the buffer size
    (void)otInstanceInit(NULL, &otInstanceBufferLength);

    // Call to allocate the buffer
    otInstanceBuffer = (uint8_t *)malloc(otInstanceBufferLength);
    assert(otInstanceBuffer);

    // Initialize OpenThread with the buffer
    instance = otInstanceInit(otInstanceBuffer, &otInstanceBufferLength);
#else
    instance = otInstanceInitSingle();
#endif
    assert(instance);

    otAppCliInit(instance);

#if OPENTHREAD_POSIX && !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    otCliSetUserCommands(kCommands, OT_ARRAY_LENGTH(kCommands), instance);
#endif

    initCustomValues(instance);
    otIp6SetEnabled(instance, true);
    otThreadSetEnabled(instance, true);

    openUdp(instance);

    if (!udpSender)
    {
        bindUdp(instance);
    }

    int counter = 0;

    while (!otSysPseudoResetWasRequested())
    {
        otTaskletsProcess(instance);
        otSysProcessDrivers(instance);

        if (udpSender && (++counter % maxTicks == 0))
        {
            sendUdp(instance);
            counter = 0;
        }
    }

    otInstanceFinalize(instance);
#if OPENTHREAD_CONFIG_MULTIPLE_INSTANCE_ENABLE
    free(otInstanceBuffer);
#endif

    goto pseudo_reset;

    return 0;
}

#if OPENTHREAD_CONFIG_LOG_OUTPUT == OPENTHREAD_CONFIG_LOG_OUTPUT_APP
void otPlatLog(otLogLevel aLogLevel, otLogRegion aLogRegion, const char *aFormat, ...)
{
    va_list ap;

    va_start(ap, aFormat);
    otCliPlatLogv(aLogLevel, aLogRegion, aFormat, ap);
    va_end(ap);
}
#endif
