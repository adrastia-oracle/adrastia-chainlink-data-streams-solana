import * as anchor from "@coral-xyz/anchor";
import { Program, AnchorProvider } from "@coral-xyz/anchor";
import { PublicKey, Transaction } from "@solana/web3.js";
import idl from "../target/idl/adrastia_chainlink_data_streams_feed_solana.json" with { type: "json" };
import type { AdrastiaChainlinkDataStreamsFeedSolana } from "../target/types/adrastia_chainlink_data_streams_feed_solana.js";
import { config as configDotEnv } from "dotenv";
import BN from "bn.js";

configDotEnv();

// ---------- Config ----------
const PROGRAM_ID = new PublicKey("ALZsBRmiqqgKtZyFgNh9iumEaWk3qn3wsiiMJiMdbvMP");

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

// ---------- PDA helpers (match your writer script) ----------
const feedPda = (feedId: Uint8Array) =>
    PublicKey.findProgramAddressSync([Buffer.from("feed"), Buffer.from(feedId)], PROGRAM_ID)[0];

const ringPda = (feedId: Uint8Array) =>
    PublicKey.findProgramAddressSync([Buffer.from("ring"), Buffer.from(feedId)], PROGRAM_ID)[0];

// ---------- Binary decode helpers ----------
function readU64LE(bytes: Uint8Array): bigint {
    let x = 0n;
    for (let i = 0; i < 8; i++) x |= BigInt(bytes[i]) << (8n * BigInt(i));
    return x;
}
function readI64LE(bytes: Uint8Array): bigint {
    let x = readU64LE(bytes);
    if (bytes[7] & 0x80) x -= 1n << 64n;
    return x;
}
function readI128LE(bytes: Uint8Array): bigint {
    let x = 0n;
    for (let i = 0; i < 16; i++) x |= BigInt(bytes[i]) << (8n * BigInt(i));
    if (bytes[15] & 0x80) x -= 1n << 128n;
    return x;
}
function u8aToAsciiTrim(bytes: Uint8Array): string {
    const end = bytes.findLastIndex((b) => b !== 0) + 1;
    return Buffer.from(bytes.slice(0, Math.max(0, end))).toString("ascii");
}
function u8aToHex(bytes: Uint8Array): string {
    return "0x" + Buffer.from(bytes).toString("hex");
}

// Insert thousands separators into a decimal string/number/bigint.
// Defaults: thousands=","  decimal="."
export function commify(value: string | number | bigint, opts: { thousands?: string; decimal?: string } = {}): string {
    const thousands = opts.thousands ?? ",";
    const decimal = opts.decimal ?? ".";

    // Prefer strings/bigints to avoid JS number precision / scientific notation
    let s = typeof value === "bigint" ? value.toString() : String(value);

    // Handle sign
    let sign = "";
    if (s.startsWith("-")) {
        sign = "-";
        s = s.slice(1);
    }

    // Split integer / fraction
    let [intPart, fracPart = ""] = s.split(".");

    // Early exit if already small
    if (intPart.length <= 3) {
        return sign + (fracPart ? intPart + decimal + fracPart : intPart);
    }

    // Build with grouping from the right
    const out: string[] = [];
    for (let i = intPart.length; i > 0; i -= 3) {
        const start = Math.max(0, i - 3);
        out.push(intPart.slice(start, i));
    }
    out.reverse();
    const withGroups = out.join(thousands);

    return sign + (fracPart ? withGroups + decimal + fracPart : withGroups);
}

// Format a fixed-point BigInt with `decimals` into a human string.
// Trims trailing zeros; keeps a leading 0 before the dot; handles negatives.
export function formatUnitsBI(value: bigint, decimals: number): string {
    const neg = value < 0n;
    let v = neg ? -value : value;

    const base = 10n ** BigInt(decimals);
    const intPart = v / base;
    let frac = (v % base).toString().padStart(decimals, "0");

    // trim trailing zeros in fractional part
    while (frac.length > 0 && frac[frac.length - 1] === "0") frac = frac.slice(0, -1);

    const body = frac.length ? `${intPart.toString()}.${frac}` : intPart.toString();
    return neg ? `-${body}` : body;
}

// Return-data decoders (Borsh layout used by your program)
function decodeLatestRoundData(buf: Uint8Array) {
    // struct LatestRoundData { u64 round_id; i128 answer; i64 started_at; i64 updated_at; u64 answered_in_round; }
    let o = 0;
    const round_id = readU64LE(buf.subarray(o, (o += 8)));
    const answer = readI128LE(buf.subarray(o, (o += 16)));
    const started = readI64LE(buf.subarray(o, (o += 8)));
    const updated = readI64LE(buf.subarray(o, (o += 8)));
    const ans_in = readU64LE(buf.subarray(o, (o += 8)));
    return { round_id, answer, started_at: started, updated_at: updated, answered_in_round: ans_in };
}

// ---------- simulate helper (to get return data) ----------
async function simulateAndGetReturn(provider: AnchorProvider, tx: Transaction): Promise<Buffer> {
    tx.feePayer = provider.wallet.publicKey;
    tx.recentBlockhash = (await provider.connection.getLatestBlockhash()).blockhash;
    const sim = await provider.connection.simulateTransaction(tx);
    const rd = sim.value.returnData;
    if (!rd) throw new Error("No returnData from simulation");
    const [base64, enc] = rd.data as [string, string];
    if (!base64) throw new Error("Empty returnData");
    return Buffer.from(base64, "base64");
}

// ---------- Read functions ----------
export async function readLatestRoundData(
    program: Program<AdrastiaChainlinkDataStreamsFeedSolana>,
    feedId: Uint8Array,
) {
    const feed = feedPda(feedId);
    const tx = await program.methods.latestRoundData().accounts({ feed }).transaction();
    const buf = await simulateAndGetReturn(program.provider as AnchorProvider, tx);
    return decodeLatestRoundData(buf);
}

export async function readRoundData(
    program: Program<AdrastiaChainlinkDataStreamsFeedSolana>,
    feedId: Uint8Array,
    roundId: bigint | number,
) {
    const feed = feedPda(feedId);
    const historyRing = ringPda(feedId);
    const tx = await program.methods
        .getRoundData(Array.from(feedId) as any, new BN(roundId.toString()))
        .accounts({ feed, historyRing })
        .transaction();
    const buf = await simulateAndGetReturn(program.provider as AnchorProvider, tx);
    return decodeLatestRoundData(buf);
}

export async function readDecimals(program: Program<AdrastiaChainlinkDataStreamsFeedSolana>, feedId: Uint8Array) {
    const feed = feedPda(feedId);
    const tx = await program.methods.decimals().accounts({ feed }).transaction();
    const buf = await simulateAndGetReturn(program.provider as AnchorProvider, tx);
    return buf[0]; // u8
}

export async function readDescription(program: Program<AdrastiaChainlinkDataStreamsFeedSolana>, feedId: Uint8Array) {
    const feed = feedPda(feedId);
    const tx = await program.methods.description().accounts({ feed }).transaction();
    const buf = await simulateAndGetReturn(program.provider as AnchorProvider, tx);
    if (buf.length !== 32) throw new Error("bad description length");
    return u8aToAsciiTrim(buf);
}

export async function readFeedId(program: Program<AdrastiaChainlinkDataStreamsFeedSolana>, feedId: Uint8Array) {
    const feed = feedPda(feedId);
    const tx = await program.methods.feedId().accounts({ feed }).transaction();
    const buf = await simulateAndGetReturn(program.provider as AnchorProvider, tx);
    if (buf.length !== 32) throw new Error("bad feedId length");
    return u8aToHex(buf);
}

// ---------- Example main ----------
async function main() {
    const provider = AnchorProvider.env();
    anchor.setProvider(provider);

    const patchedIdl = { ...idl, metadata: { ...(idl as any).metadata, address: PROGRAM_ID.toBase58() } };
    const program = new Program<AdrastiaChainlinkDataStreamsFeedSolana>(patchedIdl as any, provider);

    // pick one of your feeds (ETH/USD testnet)
    const FEED_ID_HEX = FEED_TESTNET_ETHUSD.id;
    const feedId = (() => {
        const clean = FEED_ID_HEX.startsWith("0x") ? FEED_ID_HEX.slice(2) : FEED_ID_HEX;
        const u = new Uint8Array(clean.match(/.{1,2}/g)!.map((b) => parseInt(b, 16)));
        if (u.length !== 32) throw new Error("feedId must be 32 bytes");
        return u;
    })();

    // Reads
    const [desc, dec, fid] = await Promise.all([
        readDescription(program, feedId),
        readDecimals(program, feedId),
        readFeedId(program, feedId),
    ]);
    console.log("description:", desc);
    console.log("decimals   :", dec);
    console.log("feedId     :", fid);

    const latest = await readLatestRoundData(program, feedId);
    console.log("latestRoundData:", {
        round_id: latest.round_id.toString(),
        answer: latest.answer.toString(),
        "answer_formatted (computed)": commify(formatUnitsBI(latest.answer, dec)),
        started_at: latest.started_at.toString(),
        updated_at: latest.updated_at.toString(),
        answered_in_round: latest.answered_in_round.toString(),
    });

    // Optional: fetch a specific round (e.g., latest-1)
    const prevRound = latest.round_id - 1n;
    if (prevRound > 0n) {
        const r = await readRoundData(program, feedId, prevRound);
        console.log("prevRoundData:", {
            round_id: r.round_id.toString(),
            answer: r.answer.toString(),
            "answer_formatted (computed)": commify(formatUnitsBI(r.answer, dec)),
            started_at: r.started_at.toString(),
            updated_at: r.updated_at.toString(),
            answered_in_round: r.answered_in_round.toString(),
        });
    }
}

main().catch((e) => {
    console.error(e);
    process.exit(1);
});
