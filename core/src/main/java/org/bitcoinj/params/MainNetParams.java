/*
 * Copyright 2013 Google Inc.
 * Copyright 2015 Andreas Schildbach
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.bitcoinj.params;

import org.bitcoinj.core.*;
import org.bitcoinj.net.discovery.*;

import java.net.*;

import static com.google.common.base.Preconditions.*;

/**
 * Parameters for the main production network on which people trade goods and services.
 */
public class MainNetParams extends AbstractBitcoinNetParams {
    public static final int MAINNET_MAJORITY_WINDOW = 1000;
    public static final int MAINNET_MAJORITY_REJECT_BLOCK_OUTDATED = 950;
    public static final int MAINNET_MAJORITY_ENFORCE_BLOCK_UPGRADE = 750;

    public MainNetParams() {
        super();
        targetTimespan = TARGET_TIMESPAN;
        maxTarget = Utils.decodeCompactBits(0x1d00ffffL);
        //maxTarget = Utils.decodeCompactBits(0x3d00ffffL);

        // WHAT DO WE ENTER HERE ????
        dumpedPrivateKeyHeader = 128;
        addressHeader = 0;
        p2shHeader = 5;


        segwitAddressHrp = "tbc";
        port = 8755;
        packetMagic = 0xecfacea5L;

        // WHAT DO WE ENTER HERE >>?????

        bip32HeaderP2PKHpub = 0x0768acde; // The 4 byte header that serializes in base58 to "xpub".
        bip32HeaderP2PKHpriv = 0x0768feb1; // The 4 byte header that serializes in base58 to "xprv"

        //bip32HeaderP2WPKHpub = 0x04b24746; // The 4 byte header that serializes in base58 to "zpub".
        //bip32HeaderP2WPKHpriv = 0x04b2430c; // The 4 byte header that serializes in base58 to "zprv"

        majorityEnforceBlockUpgrade = MAINNET_MAJORITY_ENFORCE_BLOCK_UPGRADE;
        majorityRejectBlockOutdated = MAINNET_MAJORITY_REJECT_BLOCK_OUTDATED;
        majorityWindow = MAINNET_MAJORITY_WINDOW;

        genesisBlock.setDifficultyTarget(0x2001ffffL);
        genesisBlock.setTime(1609074580L);
        genesisBlock.setNonce(11033477);
        id = ID_MAINNET;
        spendableCoinbaseDepth = 100;
        String genesisHash = genesisBlock.getHashAsString();

        //String x= genesisBlock.toString();
        byte[] x = genesisBlock.bitcoinSerialize();
        String X1 = Utils.HEX.encode(x);

        checkState(genesisHash.equals("480ecc7602d8989f32483377ed66381c391dda6215aeef9e80486a7fd3018075"),
                genesisHash);

        // This contains (at a minimum) the blocks which are not BIP30 compliant. BIP30 changed how duplicate
        // transactions are handled. Duplicated transactions could occur in the case where a coinbase had the same
        // extraNonce and the same outputs but appeared at different heights, and greatly complicated re-org handling.
        // Having these here simplifies block connection logic considerably.

        dnsSeeds = new String[] {
                "tidecoin.ddnsgeek.com",
                "tidecoin.theworkpc.com",

        };
        httpSeeds = new HttpDiscovery.Details[] {

        };

        // These are in big-endian format, which is what the SeedPeers code expects.
        // Updated Apr. 11th 2019
        addrSeeds = new int[] {

        };
    }

    private static MainNetParams instance;
    public static synchronized MainNetParams get() {
        if (instance == null) {
            instance = new MainNetParams();
        }
        return instance;
    }

    @Override
    public String getPaymentProtocolId() {
        return PAYMENT_PROTOCOL_ID_MAINNET;
    }
}
