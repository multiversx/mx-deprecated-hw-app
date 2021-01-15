//@flow

import type Transport from "@ledgerhq/hw-transport";

export default class Elrond {
  transport: Transport<*>;

  constructor(transport: Transport<*>, scrambleKey: string = "eGLD") {
    this.transport = transport;
    transport.decorateAppAPIMethods(
      this,
      ["getAddress", "setAddress", "signTransaction", "getAppConfiguration"],
      scrambleKey
    );
  }

  async getAddress(
    account: number,
    index: number,
    display?: boolean,
  ): Promise<{
    publicKey: string,
    address: string,
    chainCode?: string,
  }> {
    const cla = 0xed;
    const ins = 0x03;
    const p1 = display ? 0x01 : 0x00;
    const p2 = 0x00;
    const data = Buffer.alloc(8);

    data.writeInt32BE(account, 0);
    data.writeUInt32BE(index, 4);

    const response = await this.transport.send(cla, ins, p1, p2, data);

    const addressLength = response[0];
    const address = response.slice(1, 1 + addressLength).toString("ascii");

    return {address};
  }

  async setAddress(
    account: number,
    index: number,
    display?: boolean,
  ) {
    const cla = 0xed;
    const ins = 0x05;
    const p1 = display ? 0x01 : 0x00;
    const p2 = 0x00;
    const data = Buffer.alloc(8);

    data.writeInt32BE(account, 0);
    data.writeUInt32BE(index, 4);

    return await this.transport.send(cla, ins, p1, p2, data);
  }

  async signTransaction(
    rawTx: Buffer,
  ): Promise<string> {
    const curveMask = 0x80;

    const apdus = [];
    let offset = 0;

    while (offset !== rawTx.length) {
      const isFirst = offset === 0;
      const maxChunkSize = 150;

      const hasMore = offset + maxChunkSize < rawTx.length;
      const chunkSize = hasMore ? maxChunkSize : rawTx.length - offset;

      const apdu = {
        cla: 0xed,
        ins: 0x04,
        p1: isFirst ? 0x00 : 0x80,
        p2: curveMask,
        data: Buffer.alloc(chunkSize),
      };

      rawTx.copy(apdu.data, 0, offset, offset + chunkSize);

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

    if (response.length !== 67 || response[0] !== 64) {
      throw new Error("invalid signature receuved from ledger device")
    }

    return response.slice(1, response.length - 2).toString("hex");
  }

  async getAppConfiguration(): Promise<{
    version: string,
  }> {
    const response = await this.transport.send(0xed, 0x02, 0x00, 0x00);
    return {
      contractData: response[0],
      accountIndex: response[1],
      addressIndex: response[2],
      version: `${response[3]}.${response[4]}.${response[5]}`
    }
  }
}