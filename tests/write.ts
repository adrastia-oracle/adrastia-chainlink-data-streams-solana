import * as anchor from "@coral-xyz/anchor";
import { Program, AnchorProvider } from "@coral-xyz/anchor";
import { PublicKey } from "@solana/web3.js";
import idl from "../target/idl/adrastia_chainlink_data_streams_feed_solana.json" with { type: "json" };
import type { AdrastiaChainlinkDataStreamsFeedSolana } from "../target/types/adrastia_chainlink_data_streams_feed_solana.js";
import * as snappy from "snappy";
import { config as configDotEnv } from "dotenv";

configDotEnv();

// ---- Feeds ----

type Feed = {
    id: string;
    decimals: number;
    desc: string;
};

const FEED_TESTNET_BTCUSD: Feed = {
    id: "0x00037da06d56d083fe599397a4769a042d63aa73dc4ef57709d31e9971a5b439",
    decimals: 18,
    desc: "BTC/USD",
};

const FEED_TESTNET_ETHUSD: Feed = {
    id: "0x000359843a543ee2fe414dc14c7e7920ef10f4372990b79d6361cdc0dd1ba782",
    decimals: 18,
    desc: "ETH/USD",
};

// ---- Reports ----

const REPORT_TESTNET_BTCUSD_1 =
    "0x00090d9e8d96765a0c49e03a6ae05c82e8f8de70cf179baa632f18313e54bd6900000000000000000000000000000000000000000000000000000000015e63fd000000000000000000000000000000000000000000000000000000030000000100000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000022000000000000000000000000000000000000000000000000000000000000002800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000012000037da06d56d083fe599397a4769a042d63aa73dc4ef57709d31e9971a5b43900000000000000000000000000000000000000000000000000000000689bb50100000000000000000000000000000000000000000000000000000000689bb50100000000000000000000000000000000000000000000000000003f28e919a0d700000000000000000000000000000000000000000000000000308a4a1dc94daf0000000000000000000000000000000000000000000000000000000068c3420100000000000000000000000000000000000000000000196a8c4582b182bce60000000000000000000000000000000000000000000000196a5757c210f65e1f4000000000000000000000000000000000000000000000196ac13342dda51570000000000000000000000000000000000000000000000000000000000000000002c566ea33f37de72c8f8ebd4cd58cc3a178fd9f839398a8b34dd36446132e946a54fc7232d2aa3b101682f2da63bb476fd6bc1fea53a591c8e70707d1eb57fa05000000000000000000000000000000000000000000000000000000000000000233eed888ef03aca3be7a9b7c5eed1d50a848ed3de47103d8dac2f8c39cd2e7ac54f27d38c22f93a20663027e5b380fff6f7b76204c8031249bc1e4d751855584";
const REPORT_TESTNET_BTCUSD_2 =
    "0x00090d9e8d96765a0c49e03a6ae05c82e8f8de70cf179baa632f18313e54bd6900000000000000000000000000000000000000000000000000000000015ea329000000000000000000000000000000000000000000000000000000030000000100000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000022000000000000000000000000000000000000000000000000000000000000002800100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000012000037da06d56d083fe599397a4769a042d63aa73dc4ef57709d31e9971a5b43900000000000000000000000000000000000000000000000000000000689bcc0900000000000000000000000000000000000000000000000000000000689bcc0900000000000000000000000000000000000000000000000000003f6fcf019b0b0000000000000000000000000000000000000000000000000030efa43d03c4e20000000000000000000000000000000000000000000000000000000068c359090000000000000000000000000000000000000000000019716279bfed41c2290000000000000000000000000000000000000000000000197161b6b9484287bcc0000000000000000000000000000000000000000000001971633cc6924148e08000000000000000000000000000000000000000000000000000000000000000026816be68f76498ee5274846eef79d79e4b8b7b002de68cb6386981ffa69b905574dadc2d286e4e9affd133bf92dd4c3c8556fe88530224e6b07946576e9b3a310000000000000000000000000000000000000000000000000000000000000002738b2cd015bcdefce6567f1adcade87bfc81ce1c17ca913b5187978dad50718f0e19894141984cd195550c0df536bbb17649f2dd960151f789374cc6e2136002";
const REPORT_TESTNET_BTCUSD_3 =
    "0x00090d9e8d96765a0c49e03a6ae05c82e8f8de70cf179baa632f18313e54bd690000000000000000000000000000000000000000000000000000000001616f70000000000000000000000000000000000000000000000000000000030000000100000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000022000000000000000000000000000000000000000000000000000000000000002800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000012000037da06d56d083fe599397a4769a042d63aa73dc4ef57709d31e9971a5b43900000000000000000000000000000000000000000000000000000000689cd2fd00000000000000000000000000000000000000000000000000000000689cd2fd00000000000000000000000000000000000000000000000000003d5c5676dda6000000000000000000000000000000000000000000000000002febd610845c4f0000000000000000000000000000000000000000000000000000000068c45ffd0000000000000000000000000000000000000000000019cd69b75ee5e0be5a000000000000000000000000000000000000000000000019cd6787b1bf4165cc400000000000000000000000000000000000000000000019cd6be70c0c8016e7c00000000000000000000000000000000000000000000000000000000000000002f1b56404dbe0ffca18c0d83a3ff63c8798472858f3555d80670695cdea0b381120caf0b0589b9fe63d6b2404b1978c403e5fc32b550fa35b4b20257dd710c2010000000000000000000000000000000000000000000000000000000000000002312940d156ba44be82f4dbea2ba8b411e1076e9bf613f0afff7979f5ba3343d15b02c665c99712b01891b828aa598fbe4bee64d2c8b515a8c5f1d0234df3fb8d";

const REPORT_TESTNET_ETHUSD_1 =
    "0x00090d9e8d96765a0c49e03a6ae05c82e8f8de70cf179baa632f18313e54bd6900000000000000000000000000000000000000000000000000000000015e63fd000000000000000000000000000000000000000000000000000000030000000100000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000220000000000000000000000000000000000000000000000000000000000000028001010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000120000359843a543ee2fe414dc14c7e7920ef10f4372990b79d6361cdc0dd1ba78200000000000000000000000000000000000000000000000000000000689bb50100000000000000000000000000000000000000000000000000000000689bb50100000000000000000000000000000000000000000000000000003f28e919a0d700000000000000000000000000000000000000000000000000308a4a1dc94daf0000000000000000000000000000000000000000000000000000000068c342010000000000000000000000000000000000000000000000f9cc6355e4801880000000000000000000000000000000000000000000000000f9c584d3f463cbe4700000000000000000000000000000000000000000000000f9d02d487f821800000000000000000000000000000000000000000000000000000000000000000002d33682dd11d62313709107a65f2c57ad0adacfd0388158ff39e23ffd21f130dd71aff040d72202e59a46a1fd4b7bbf07c88ce6207e3980a7773ee4c7a4b22e6d000000000000000000000000000000000000000000000000000000000000000270213d484c45479c0539f460c3d8110c8f6fd67f81e47ee0b3df59da4ff3533c448af68ec1a33f240c235bf94fbff2d3abbb43a866dbdabd18e9154e14d682eb";
const REPORT_TESTNET_ETHUSD_2 =
    "0x00090d9e8d96765a0c49e03a6ae05c82e8f8de70cf179baa632f18313e54bd6900000000000000000000000000000000000000000000000000000000015ea329000000000000000000000000000000000000000000000000000000030000000100000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000220000000000000000000000000000000000000000000000000000000000000028000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000120000359843a543ee2fe414dc14c7e7920ef10f4372990b79d6361cdc0dd1ba78200000000000000000000000000000000000000000000000000000000689bcc0900000000000000000000000000000000000000000000000000000000689bcc0900000000000000000000000000000000000000000000000000003f6fcf019b0b0000000000000000000000000000000000000000000000000030efa43d03c4e20000000000000000000000000000000000000000000000000000000068c359090000000000000000000000000000000000000000000000f8b535738767e100000000000000000000000000000000000000000000000000f8b37aa5f5f6b181400000000000000000000000000000000000000000000000f8b754a944d20940000000000000000000000000000000000000000000000000000000000000000002b353d9c4a18ab2a7639779a206d3cc5605a5975122794f275cb6622632c3f3674fcf96d7e3d2cff32d171ebfd46d4222532b3132c257383fc72f81da20777305000000000000000000000000000000000000000000000000000000000000000267c3ac647570e2adcc6c06efc2b8c058fbac56f7b9a233db8c81fd74bcc24f9c71840fb040afc0039ac82f5b60a2ba656dbccba9ede2c8b644bf6ccbd489942e";
const REPORT_TESTNET_ETHUSD_3 =
    "0x00090d9e8d96765a0c49e03a6ae05c82e8f8de70cf179baa632f18313e54bd690000000000000000000000000000000000000000000000000000000001616f70000000000000000000000000000000000000000000000000000000030000000100000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000220000000000000000000000000000000000000000000000000000000000000028000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000120000359843a543ee2fe414dc14c7e7920ef10f4372990b79d6361cdc0dd1ba78200000000000000000000000000000000000000000000000000000000689cd2fd00000000000000000000000000000000000000000000000000000000689cd2fd00000000000000000000000000000000000000000000000000003d5c5676dda6000000000000000000000000000000000000000000000000002febd610845c4f0000000000000000000000000000000000000000000000000000000068c45ffd0000000000000000000000000000000000000000000001011f5f560c51e370e00000000000000000000000000000000000000000000001011f453b71a1a73640000000000000000000000000000000000000000000000101220bfe5434b334c000000000000000000000000000000000000000000000000000000000000000022e715bb131dca95eb10cf8d99589175824301cf18d717ce68b6285509602283db4d367087043356e4bfa7cb3f8b00b3a98d6ffec8bdaba8a8b379c514bd428cb00000000000000000000000000000000000000000000000000000000000000023639aad1291041efbe99b6b83f1bdd596704af0e14b06f5ab65929d27c10d02b5b28dd1a1ba07959524297be35ed6698184ab09e771c13c76ba3a9ed929b8111";

// ---- IDs ----
// Your program (this repo)
const PROGRAM_ID = new PublicKey("ALZsBRmiqqgKtZyFgNh9iumEaWk3qn3wsiiMJiMdbvMP");

const BOOTSTRAP_ADMIN = new PublicKey("634xiC5wufdbogSag2Q5koeRvJuUBQJ8vaU9j376oL2Q");

// Chainlink Verifier tuple (use the right cluster values)
const VERIFIER_PROGRAM_ID = new PublicKey("Gt9S41PtjR58CbG9JhJ3J6vxesqrNAswbWYbLNTMZA3c");
const ACCESS_CONTROLLER = new PublicKey("2k3DsgwBoqrnvXKVvd7jX7aptNxdcRBdcd5HkYsGgbrb"); // devnet example

// ---- Helpers ----
const feedPda = (feedId: Uint8Array) =>
    PublicKey.findProgramAddressSync([Buffer.from("feed"), Buffer.from(feedId)], PROGRAM_ID)[0];

const ringPda = (feedId: Uint8Array) =>
    PublicKey.findProgramAddressSync([Buffer.from("ring"), Buffer.from(feedId)], PROGRAM_ID)[0];

const configPda = () => PublicKey.findProgramAddressSync([Buffer.from("config")], PROGRAM_ID)[0];

const verifierPda = () => PublicKey.findProgramAddressSync([Buffer.from("verifier")], VERIFIER_PROGRAM_ID)[0];

const hexToU8a = (hex: string) => {
    const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
    if (!/^[0-9a-fA-F]+$/.test(clean)) throw new Error("Invalid hex string");
    return new Uint8Array(clean.match(/.{1,2}/g)!.map((b) => parseInt(b, 16)));
};

const ascii32 = (s: string) => {
    const b = Buffer.alloc(32);
    const src = Buffer.from(s, "ascii");
    src.copy(b, 0, 0, Math.min(src.length, 32));
    return new Uint8Array(b);
};

const bytes32 = (hex32: string) => {
    const u = hexToU8a(hex32);
    if (u.length !== 32) throw new Error("feedId must be 32 bytes");
    return u;
};

async function ensureFeedAndRing(
    program: Program<AdrastiaChainlinkDataStreamsFeedSolana>,
    adminPubkey: PublicKey,
    feedId: Uint8Array,
    decimals: number,
    descriptionAscii32: Uint8Array,
) {
    const config = configPda();
    const feed = feedPda(feedId);
    const ring = ringPda(feedId);

    let needsInitialConfig = false;
    try {
        await program.account.programConfig.fetch(config);
    } catch {
        needsInitialConfig = true;
    }
    if (needsInitialConfig) {
        console.log("Initializing program config...");

        await program.methods
            .initProgramConfig()
            .accountsPartial({
                config: configPda(),
                admin: BOOTSTRAP_ADMIN,
                payer: adminPubkey,
            })
            .rpc();
    }

    // Quick existence checks (cheap & cheerful)
    let needsFeed = false;
    try {
        await program.account.feed.fetch(feed);
    } catch {
        needsFeed = true;
    }

    if (needsFeed) {
        console.log("Attempting to init feed...");

        await program.methods
            .initFeed(Array.from(feedId) as any, decimals, Array.from(descriptionAscii32) as any)
            .accounts({
                admin: adminPubkey,
                verifierProgramId: VERIFIER_PROGRAM_ID,
                verifierAccount: verifierPda(),
                accessController: ACCESS_CONTROLLER,
                payer: adminPubkey,
            })
            .rpc({ commitment: "confirmed" });
    }

    let needsRing = false;
    try {
        await program.account.historyRing.fetch(ring);
    } catch {
        needsRing = true;
    }

    if (needsRing) {
        console.log("Attempting to init history ring...");

        const info = await program.provider.connection.getAccountInfo(ring);
        console.log("Ring info:", {
            ring: ring.toBase58(),
            exists: !!info,
            owner: info?.owner?.toBase58(),
            len: info?.data.length,
        });

        const space = 8 + 64 + 512 * 48;
        const rent = await program.provider.connection.getMinimumBalanceForRentExemption(space);
        console.log("Estimated rent:", { space, rent });

        const currentLamports = await program.provider.connection.getBalance(adminPubkey);
        console.log("Current lamports:", { currentLamports });

        await program.methods
            .initHistoryRing(Array.from(feedId) as any)
            .accountsPartial({
                feed,
                historyRing: ring,
                admin: adminPubkey,
                payer: adminPubkey,
                systemProgram: anchor.web3.SystemProgram.programId,
            })
            .rpc({ commitment: "confirmed" });
    }

    return { feed, ring };
}

async function main() {
    // Provider & program
    const provider = AnchorProvider.env();
    anchor.setProvider(provider);

    // Override the program ID in the IDL
    const patchedIdl = { ...idl, metadata: { ...(idl as any).metadata, address: PROGRAM_ID.toBase58() } };

    const program = new Program<AdrastiaChainlinkDataStreamsFeedSolana>(patchedIdl as any, provider);

    // -------------------------------
    // Example inputs (edit these)
    // -------------------------------
    const feedMetadata = FEED_TESTNET_ETHUSD;
    const feedReport = REPORT_TESTNET_ETHUSD_2;

    const feedId = bytes32(feedMetadata.id);
    const decimals = feedMetadata.decimals;
    const description = ascii32(feedMetadata.desc);

    const signedReport = hexToU8a(feedReport);

    // The Verifier expects the signed report to be snappy-compressed
    const compressedReport = await snappy.compress(Buffer.from(signedReport));

    // Derive Verifier state PDA (“verifier”) and config PDA from the report’s first 32 bytes
    const VERIFIER_ACCOUNT = verifierPda();
    const CONFIG_ACCOUNT = PublicKey.findProgramAddressSync(
        [signedReport.slice(0, 32)], // uncompressed slice
        VERIFIER_PROGRAM_ID,
    )[0];

    console.log("Verifier PDA:", VERIFIER_ACCOUNT.toBase58());
    console.log("Config PDA:", CONFIG_ACCOUNT.toBase58());

    // Ensure feed + history ring exist
    const { feed, ring } = await ensureFeedAndRing(program, provider.wallet.publicKey, feedId, decimals, description);

    try {
        console.log("\n📝 Transaction Details");
        console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        console.log("🔑 Signer:", provider.wallet.publicKey.toString());

        const tx = await program.methods
            .verifyAndUpdateReport(Array.from(feedId) as any, Buffer.from(compressedReport))
            .accounts({
                verifierProgramId: VERIFIER_PROGRAM_ID,
                verifierAccount: VERIFIER_ACCOUNT,
                accessController: ACCESS_CONTROLLER,
                user: provider.wallet.publicKey,
                configAccount: CONFIG_ACCOUNT,
            })
            .rpc({ commitment: "confirmed" });

        console.log("✅ Transaction successful!");
        console.log("🔗 Signature:", tx);

        // Fetch and display logs
        const txDetails = await provider.connection.getTransaction(tx, {
            commitment: "confirmed",
            maxSupportedTransactionVersion: 0,
        });

        console.log("\n📋 Program Logs");
        console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

        let indentLevel = 0;
        txDetails!.meta!.logMessages!.forEach((log) => {
            if (log.includes("Program invoke")) {
                console.log("  ".repeat(indentLevel) + "🔄", log.trim());
                indentLevel++;
                return;
            }
            if (log.includes("Program return") || log.includes("Program consumed")) {
                indentLevel = Math.max(0, indentLevel - 1);
            }
            const indent = "  ".repeat(indentLevel);
            if (log.includes("Program log:")) {
                const logMessage = log.replace("Program log:", "").trim();
                console.log(indent + "📍", logMessage);
            } else if (log.includes("Program data:")) {
                console.log(indent + "📊", log.replace("Program data:", "").trim());
            }
        });
        console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    } catch (error) {
        console.log("\n❌ Transaction Failed");
        console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        console.error("Error:", error);
        console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    }
}

main().catch((e) => {
    console.error(e);
    process.exit(1);
});
