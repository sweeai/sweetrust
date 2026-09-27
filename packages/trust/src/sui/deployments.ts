import type { KernelConfig } from "./builders.ts"

/**
 * The swee_kernel deployment on Sui TESTNET (published 2026-07-20; verified
 * live 2026-09-26: `spend_cage` signatures match these builders and the
 * ProtocolState is not paused). There is no mainnet deployment yet.
 */
export const TESTNET_KERNEL: KernelConfig = {
  kernelPackageId: "0x01d90f7ae7347a1b4aca581fc7905704b9ac32a626600261a4f4e33a2ddb7274",
  protocolStateId: "0x91e6e5ec19f66ac3a479e6c57ab2973b494d81b0380270f3cbc10c21a30669fd",
}

export const TESTNET_FULLNODE = "https://fullnode.testnet.sui.io:443"
