import type Transport from "@ledgerhq/hw-transport";

const CLA = 0xed;
const SIGN_RAW_TX_INS = 0x04;
const SIGN_HASH_TX_INS = 0x07;
const SIGN_MESSAGE_INS = 0x06;
const PROVIDE_ESDT_INFO_INS = 0x08;
const GET_ADDRESS_AUTH_TOKEN_INS = 0x09;

const ACTIVE_SIGNERS = [
  SIGN_RAW_TX_INS,
  SIGN_HASH_TX_INS,
  SIGN_MESSAGE_INS,
  GET_ADDRESS_AUTH_TOKEN_INS,
];

export default class Elrond {
  transport: Transport;

  constructor(transport: Transport, scrambleKey: string = "eGLD") {
    this.transport = transport;
    transport.decorateAppAPIMethods(
      this,
      [
        "getAddress",
        "setAddress",
        "signTransaction",
        "signMessage",
        "getAppConfiguration",
        "getAddressAndSignAuthToken",
        "provideESDTInfo",
      ],
      scrambleKey
    );
  }

  async getAddress(
    account: number,
    index: number,
    display?: boolean
  ): Promise<{ address: string }> {
    const ins = 0x03;
    const p1 = display ? 0x01 : 0x00;
    const p2 = 0x00;
    const data = Buffer.alloc(8);

    data.writeInt32BE(account, 0);
    data.writeUInt32BE(index, 4);

    const response = await this.transport.send(CLA, ins, p1, p2, data);

    const addressLength = response[0];
    const address = response.slice(1, 1 + addressLength).toString("ascii");

    return { address };
  }

  async setAddress(account: number, index: number, display?: boolean) {
    const ins = 0x05;
    const p1 = display ? 0x01 : 0x00;
    const p2 = 0x00;
    const data = Buffer.alloc(8);

    data.writeInt32BE(account, 0);
    data.writeUInt32BE(index, 4);

    return await this.transport.send(CLA, ins, p1, p2, data);
  }

  async signTransaction(rawTx: Buffer, usingHash: boolean): Promise<string> {
    return usingHash
      ? this.sign(rawTx, SIGN_HASH_TX_INS)
      : this.sign(rawTx, SIGN_RAW_TX_INS);
  }

  async signMessage(message: Buffer): Promise<string> {
    return this.sign(message, SIGN_MESSAGE_INS);
  }

  async getAddressAndSignAuthToken(
    account: number,
    index: number,
    token: Buffer
  ): Promise<{
    address: string;
    signature: string;
  }> {
    const data = Buffer.alloc(12);

    data.writeInt32BE(account, 0);
    data.writeUInt32BE(index, 4);
    data.writeUInt32BE(token.length, 8);

    let buffersArray = [data, token];
    let result = await this.sign(
      Buffer.concat(buffersArray),
      GET_ADDRESS_AUTH_TOKEN_INS
    );

    let splitRes = result.split("|");
    return {
      address: splitRes[0],
      signature: splitRes[1],
    };
  }

  async getAppConfiguration(): Promise<{
    contractData: number;
    accountIndex: number;
    addressIndex: number;
    version: string;
  }> {
    /*
    byte 0 -> is contract data enabled?
    bytes 1,2 -> unused (kept for compatibility reasons)
    bytes 3,4,5 -> app version
    bytes 6,7,8,9 -> account index (big endian)     -> only for versions >= 1.0.16
    bytes 10,11,12,13 -> address index (big endian) -> only for versions >= 1.0.16
    */
    const response = await this.transport.send(0xed, 0x02, 0x00, 0x00);
    let accountIndex = 0;
    let addressIndex = 0;
    if(response.length === 14){ // check if the response if from a version newer than 1.0.16
      accountIndex = this.getIntValueFromBytes(response.slice(6, 10));
      addressIndex = this.getIntValueFromBytes(response.slice(10, 14));
    }
    return {
      contractData: response[0],
      accountIndex: accountIndex,
      addressIndex: addressIndex,
      version: `${response[3]}.${response[4]}.${response[5]}`,
    };
  }

  getIntValueFromBytes(buffer: Buffer) {
    return ((buffer[buffer.length - 1]) |
      (buffer[buffer.length - 2] << 8) |
      (buffer[buffer.length - 3] << 16) |
      (buffer[buffer.length - 4] << 24));
  }

  async sign(message: Buffer, type: number): Promise<string> {
    if (!ACTIVE_SIGNERS.includes(type)) {
      throw new Error(`invalid sign instruction called: ${type}`);
    }

    const apdus = [];
    let offset = 0;

    while (offset !== message.length) {
      const isFirst = offset === 0;
      const maxChunkSize = 150;

      const hasMore = offset + maxChunkSize < message.length;
      const chunkSize = hasMore ? maxChunkSize : message.length - offset;

      const apdu = {
        cla: CLA,
        ins: type,
        p1: isFirst ? 0x00 : 0x80,
        p2: 0x00,
        data: Buffer.alloc(chunkSize),
      };

      message.copy(apdu.data, 0, offset, offset + chunkSize);

      apdus.push(apdu);
      offset += chunkSize;
    }

    let response = Buffer.alloc(0);
    for (let apdu of apdus) {
      response = await this.transport.send(
        apdu.cla,
        apdu.ins,
        apdu.p1,
        apdu.p2,
        apdu.data
      );
    }

    if (GET_ADDRESS_AUTH_TOKEN_INS === type) {
      return this.handleAuthTokenResponse(response);
    }

    if (response.length !== 67 || response[0] !== 64) {
      throw new Error("invalid signature received from ledger device");
    }

    return response.slice(1, response.length - 2).toString("hex");
  }

  async handleAuthTokenResponse(response: Buffer): Promise<string> {
    if (response.length !== 129 && response[0] !== 126) {
      throw new Error(
        "invalid address and token signature received from ledger device"
      );
    }

    const address = response.slice(1, 63).toString("ascii");
    const signature = response.slice(63, response.length - 2).toString("hex");
    return address + "|" + signature;
  }

  serializeESDTInfo(
    ticker: string,
    id: string,
    decimals: number,
    chainId: string,
    signature: string
  ): Buffer {
    const tickerLengthBuffer = Buffer.from([ticker.length]);
    const tickerBuffer = Buffer.from(ticker);
    const idLengthBuffer = Buffer.from([id.length]);
    const idBuffer = Buffer.from(id);
    const decimalsBuffer = Buffer.from([decimals]);
    const chainIdLengthBuffer = Buffer.from([chainId.length]);
    const chainIdBuffer = Buffer.from(chainId);
    const signatureBuffer = Buffer.from(signature, "hex");
    let infoBuffer = [
      tickerLengthBuffer,
      tickerBuffer,
      idLengthBuffer,
      idBuffer,
      decimalsBuffer,
      chainIdLengthBuffer,
      chainIdBuffer,
      signatureBuffer,
    ];
    return Buffer.concat(infoBuffer);
  }

  async provideESDTInfo(
    ticker: string,
    id: string,
    decimals: number,
    chainId: string,
    signature: string
  ): Promise<any> {
    const data = this.serializeESDTInfo(
      ticker,
      id,
      decimals,
      chainId,
      signature
    );

    return await this.transport.send(
      CLA,
      PROVIDE_ESDT_INFO_INS,
      0x00,
      0x00,
      data
    );
  }
}
