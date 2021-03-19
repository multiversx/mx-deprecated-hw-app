//@flow

import type Transport from "@ledgerhq/hw-transport";

const SIGN_RAW_TX_INS = 0x04;
const SIGN_HASH_TX_INS = 0x07;
const SIGN_MESSAGE_INS = 0x06;

const ACTIVE_SIGNERS = [
    SIGN_RAW_TX_INS,
    SIGN_HASH_TX_INS,
    SIGN_MESSAGE_INS
];

export default class Elrond {
    transport: Transport<*>;

    constructor(transport: Transport<*>, scrambleKey: string = "eGLD") {
        this.transport = transport;
        transport.decorateAppAPIMethods(
            this,
            ["getAddress", "setAddress", "signTransaction", "signMessage", "getAppConfiguration"],
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
        usingHash: boolean,
    ): Promise<string> {
        return usingHash ? this.sign(rawTx, SIGN_HASH_TX_INS) :
          this.sign(rawTx, SIGN_RAW_TX_INS);
    }

    async signMessage(message: Buffer): Promise<string> {
        return this.sign(message, SIGN_MESSAGE_INS);
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

    async sign(message: Buffer, type: number): Promise<string> {
        if ( !ACTIVE_SIGNERS.includes(type) ) {
            throw new Error(`invalid sign instruction called: ${type}`);
        }

        const curveMask = 0x80;

        const apdus = [];
        let offset = 0;

        while (offset !== message.length) {
            const isFirst = offset === 0;
            const maxChunkSize = 150;

            const hasMore = offset + maxChunkSize < message.length;
            const chunkSize = hasMore ? maxChunkSize : message.length - offset;

            const apdu = {
                cla: 0xed,
                ins: type,
                p1: isFirst ? 0x00 : 0x80,
                p2: curveMask,
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

        if (response.length !== 67 || response[0] !== 64) {
            throw new Error("invalid signature received from ledger device")
        }

        return response.slice(1, response.length - 2).toString("hex");
    }
}
