const bitcoin = require("bitcoinjs-lib");
const ecc = require("tiny-secp256k1");
const ECPairFactory = require("ecpair").default;
const fs = require("fs");
const path = require("path");

bitcoin.initEccLib(ecc);
const ECPair = ECPairFactory(ecc);

const network = bitcoin.networks.testnet;

function genTaproot() {
  const keyPair = ECPair.makeRandom({ network });

  // compressed pubkey (33 bytes) → x-only (32 bytes)
  const pubkey = Buffer.from(keyPair.publicKey);
  const internal = pubkey.slice(1, 33); // drop 0x02/0x03 prefix

  const p2tr = bitcoin.payments.p2tr({ internalPubkey: internal, network });

  const address = p2tr.address;
  const wif = keyPair.toWIF();
  const privHex = Buffer.from(keyPair.privateKey).toString("hex");
  const scriptPubKeyHex = bitcoin.address
    .toOutputScript(address, network)
    .toString("hex");

  console.log({
    address,
    wif,
    privHex,
    internal: internal.toString("hex"),
    scriptPubKeyHex,
  });

  const wallet = {
    network: "testnet",
    address,
    wif,
    privHex,
    internal: internal.toString("hex"),
    scriptPubKeyHex,
    updatedAt: new Date().toISOString(),
  };

  const outPath = path.join(__dirname, "wallet.json");
  fs.writeFileSync(outPath, JSON.stringify(wallet, null, 2));
}

genTaproot();
