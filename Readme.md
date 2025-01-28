# Merkle Mountain Range Implementation in o1.js

This project demonstrates how to implement a Merkle Mountain Range (MMR) using o1.js for zkApps on the Mina Protocol. It showcases how to manage off-chain data structures while ensuring on-chain data integrity through cryptographic commitments, leveraging the power of zk-SNARKs.

## Installation

Clone the repository and install the dependencies using npm:

```bash
# Clone the repository
git clone https://github.com/codekaya/Mina_MMR
cd Mina_MMR

# Install dependencies
npm install

# Ensure o1.js is installed
npm install o1js

# Run test cases to verify the MMR implementation:
npm run test

```

## License

[Apache-2.0](LICENSE)


Merkle Mountain Range (MMR) in o1.js
====================================

This project demonstrates how to implement a [Merkle Mountain Range (MMR)](https://github.com/opentimestamps/opentimestamps-server/blob/master/doc/merkle-mountain-range.md) using o1.js for zkApps on the Mina Protocol. It showcases how to manage large off-chain data structures while ensuring on-chain data integrity through cryptographic commitments, leveraging the power of zk-SNARKs.

Table of Contents
-----------------

1.  [Overview](#overview)
2.  [Project Structure](#project-structure)
3.  [Installation](#installation)
4.  [Usage](#usage)
    -   [Off-chain MMR Management](#off-chain-mmr-management)
    -   [On-chain Root Commitment](#on-chain-root-commitment)
    -   [Verifying Inclusion On-chain](#verifying-inclusion-on-chain)
5.  [Example zkApp Flow](#example-zkapp-flow)
6.  [Run the Example Code](#run-the-example-code)
7.  [License](#license)

* * * * *

Overview
--------

**Merkle Mountain Ranges** are an append-only data structure composed of multiple "peaks" (perfect binary trees). They allow efficient proofs of inclusion while permitting new leaves to be appended without having to rebuild the entire structure. In the **Mina Protocol** context, MMRs are ideal when you want to keep large datasets off-chain but still prove individual items' membership on-chain.

With **o1.js**, we can build an MMR in JavaScript or TypeScript, perform all heavy operations off-chain, and only store (or verify) the MMR's root (commitment) inside the zkApp's on-chain state. This aligns perfectly with Mina's design principle: keep on-chain data minimal, while leveraging powerful zk-SNARK proofs to ensure correctness.

* * * * *

Project Structure
-----------------

scss

KopyalaDüzenle

`Mina_MMR/
  ├─ src/
  │   ├─ Mmr.ts            // Core MMR logic (append, getProof, verifyProof, etc.)
  │   ├─ MMRContract.ts    // Minimal zkApp storing MMR root on-chain
  │   └─ index.ts          // Example usage: off-chain building + on-chain usage
  ├─ test/
  │   └─ ...               // Test files (if any)
  ├─ package.json
  ├─ tsconfig.json
  ├─ README.md
  ...`

1.  **`Mmr.ts`**\
    Contains the `MerkleMountainRange` class. This is where you append leaves, generate proofs, verify proofs, and manage the internal data (e.g., storing all node hashes).

2.  **`MMRContract.ts`**\
    A simple zkApp (`SmartContract`) that has a single `@state(Field)` variable for the MMR root. It includes a method to update the stored root and a (commented) example method for verifying a leaf's inclusion proof.

3.  **`index.ts`**\
    Demonstrates how to:

    -   Set up a local Mina blockchain.
    -   Deploy the `MMRContract`.
    -   Build an MMR off-chain (append leaves, get root).
    -   Commit the root on-chain.
    -   Generate and (optionally) verify an inclusion proof on-chain.

* * * * *

Installation
------------

1.  **Clone the repository**

bash

KopyalaDüzenle

`git clone https://github.com/codekaya/Mina_MMR
cd Mina_MMR`

1.  **Install dependencies**

bash

KopyalaDüzenle

`npm install`

1.  **Ensure `o1.js` is installed**\
    (It should already be included in `package.json`, but just in case):

bash

KopyalaDüzenle

`npm install o1js`

1.  **(Optional) Run tests**\
    If you have test files in the `test` directory, run:

bash

KopyalaDüzenle

`npm run test`

* * * * *

Usage
-----

### Off-chain MMR Management

1.  **Create an MMR instance**

    ts

    KopyalaDüzenle

    `import { MerkleMountainRange } from './Mmr.js';
    import { Field } from 'o1js';

    // Off-chain
    const mmr = new MerkleMountainRange();

    // Append leaves
    mmr.append(Field(10));
    mmr.append(Field(20));
    mmr.append(Field(30));

    // Current MMR root
    const currentRoot = mmr.rootHash;
    console.log('Current MMR Root:', currentRoot.toString());`

2.  **Generate an Inclusion Proof**

    ts

    KopyalaDüzenle

    `import { UInt64 } from 'o1js';

    // For the second leaf (Field(20)), the index is 2
    const proof = mmr.getProof(UInt64.from(2));
    console.log('Proof', proof);`

3.  **Verify the proof off-chain**

    ts

    KopyalaDüzenle

    `const leaf = Field(20);
    const isValid = mmr.verifyProof(leaf, proof);

    console.log('Proof is valid off-chain?', isValid.toBoolean());`

### On-chain Root Commitment

For larger MMRs, storing every node hash on-chain becomes infeasible. Instead, we:

-   Maintain the MMR **off-chain** (in JavaScript/TypeScript, a database, etc.).
-   Only **commit** the root hash (plus maybe some additional info) **on-chain**.

In `MMRContract.ts`, we store:

ts

KopyalaDüzenle

`@state(Field) mmrRoot = State<Field>();`

and expose methods:

-   `init()` -- sets `mmrRoot` to `Field(0)`.
-   `updateRoot(newRoot: Field)` -- updates the on-chain root to `newRoot`.

### Verifying Inclusion On-chain

To check if a leaf exists in the MMR **on-chain**, you'd:

1.  Generate a proof off-chain with `mmr.getProof(index)`.
2.  Pass the leaf, proof, and relevant data to a zkApp method like `verifyInclusion(...)`.
3.  Inside the zkApp, reconstruct the root from the leaf + proof and compare it with the stored `mmrRoot`.

A simplified example method is shown in `MMRContract.ts` (commented out in the code for reference):

ts

KopyalaDüzenle

`@method verifyInclusion( leaf: Field,
  siblings: Field[],
  peaks: Field[],
  index: Field ) {
  // 1) Retrieve the stored root
  let rootStored = this.mmrRoot.get();
  this.mmrRoot.assertEquals(rootStored);

  // 2) Recompute the hash from leaf + siblings
  let hash = leaf;
  for (const sibling of siblings) {
    hash = Poseidon.hash([hash, sibling]);
  }

  // 3) Combine with peaks, or do "bag the peaks" logic
  let computedRoot = hash;
  for (const peak of peaks) {
    computedRoot = Poseidon.hash([computedRoot, peak]);
  }

  // 4) Check equality
  computedRoot.assertEquals(rootStored);
}`

* * * * *

Example zkApp Flow
------------------

Below is a high-level flow illustrating **"Off-chain MMR, On-chain Root"**:

1.  **Off-chain**: Build the MMR (`append` leaves, `getProof`).
2.  **On-chain**: Deploy `MMRContract`, storing only `mmrRoot`.
3.  **Off-chain**: Generate an inclusion proof for a leaf you want to prove.
4.  **On-chain**: Call a method on `MMRContract` (e.g., `verifyInclusion`) with the leaf/proof data. Recompute the root in the circuit, confirm it matches the stored root.

That's it! This workflow keeps circuit size minimal while enabling trustless verification of membership.

* * * * *

Run the Example Code
--------------------

1.  **Compile and Deploy** (from `index.ts`)

    bash

    KopyalaDüzenle

    `# in the root project directory
    npx tsc `

2.  **Execute `index.ts`** (example script)

    bash

    KopyalaDüzenle

    `node dist/src/index.js`

    This script:

    -   Sets up a local Mina blockchain with `Mina.LocalBlockchain()`.
    -   Deploys the MMRContract (with `mmrRoot = Field(0)`).
    -   Builds an MMR off-chain (3 leaves).
    -   Commits the final root on-chain.
    -   Generates a proof for the second leaf (Field(20)).
    -   (Optionally) Verifies the proof on-chain (in the commented section).

You should see output in your console, including a successful log for the MMR proof verification (if un-commented in the code).

* * * * *

License
-------

This project is licensed under the [Apache 2.0 License](LICENSE) (see the LICENSE file for details).

* * * * *

### Further Reading / Proposal

For a more detailed explanation, including a roadmap, milestones, and deeper insight into how this MMR library can be extended or integrated into larger zkApp projects, please see the accompanying **proposal** in the repository.

* * * * *

**Happy coding!** If you have any questions or run into issues, feel free to open an issue on GitHub or reach out via the Mina community channels.