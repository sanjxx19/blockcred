const { expect } = require('chai');
const { ethers } = require('hardhat');
const { loadFixture, time } = require('@nomicfoundation/hardhat-toolbox/network-helpers');
const { anyValue } = require('@nomicfoundation/hardhat-chai-matchers/withArgs');
const { StandardMerkleTree } = require('@openzeppelin/merkle-tree');

const DID = 'did:web:college-a.example';
const DID_HASH = ethers.id(DID);
const VCT = 'urn:blockcred:vct:degree:v1';
const Status = { None: 0, Active: 1, Suspended: 2, Revoked: 3 };

async function deployFixture() {
  const [admin, governor, controller, other, newController] = await ethers.getSigners();
  const IssuerRegistry = await ethers.getContractFactory('IssuerRegistry');
  const registry = await IssuerRegistry.deploy(admin.address, [governor.address]);
  const registryAddress = await registry.getAddress();
  const revocation = await (await ethers.getContractFactory('RevocationRegistry')).deploy(registryAddress);
  const anchor = await (await ethers.getContractFactory('MerkleAnchor')).deploy(registryAddress);
  return { registry, revocation, anchor, admin, governor, controller, other, newController };
}

async function withIssuerFixture() {
  const ctx = await deployFixture();
  await ctx.registry.connect(ctx.governor).registerIssuer(DID, ctx.controller.address, 'ipfs://meta');
  await ctx.registry.connect(ctx.governor).registerSchema(ethers.id(VCT), VCT);
  return ctx;
}

describe('IssuerRegistry', () => {
  it('assigns roles in the constructor', async () => {
    const { registry, admin, governor } = await loadFixture(deployFixture);
    expect(await registry.hasRole(await registry.DEFAULT_ADMIN_ROLE(), admin.address)).to.equal(true);
    expect(await registry.hasRole(await registry.GOVERNOR_ROLE(), governor.address)).to.equal(true);
    expect(await registry.hasRole(await registry.GOVERNOR_ROLE(), admin.address)).to.equal(false);
  });

  it('lets governors register issuers and emits events', async () => {
    const { registry, governor, controller } = await loadFixture(deployFixture);
    await expect(registry.connect(governor).registerIssuer(DID, controller.address, ''))
      .to.emit(registry, 'IssuerRegistered')
      .withArgs(DID_HASH, DID, controller.address, '')
      .and.to.emit(registry, 'IssuerStatusChanged')
      .withArgs(DID_HASH, Status.None, Status.Active);
    expect(await registry.isAccredited(DID_HASH)).to.equal(true);
    expect(await registry.isAccreditedDid(DID)).to.equal(true);
    expect(await registry.didHashOf(DID)).to.equal(DID_HASH);
    expect(await registry.issuerCount()).to.equal(1n);
  });

  it('rejects non-governors, duplicates, empty DIDs and zero controllers', async () => {
    const { registry, governor, controller, other } = await loadFixture(deployFixture);
    await expect(registry.connect(other).registerIssuer(DID, controller.address, ''))
      .to.be.revertedWithCustomError(registry, 'AccessControlUnauthorizedAccount')
      .withArgs(other.address, await registry.GOVERNOR_ROLE());
    await expect(registry.connect(governor).registerIssuer('', controller.address, '')).to.be.revertedWithCustomError(
      registry,
      'EmptyDid',
    );
    await expect(registry.connect(governor).registerIssuer(DID, ethers.ZeroAddress, '')).to.be.revertedWithCustomError(
      registry,
      'ZeroAddress',
    );
    await registry.connect(governor).registerIssuer(DID, controller.address, '');
    await expect(registry.connect(governor).registerIssuer(DID, controller.address, ''))
      .to.be.revertedWithCustomError(registry, 'IssuerAlreadyRegistered')
      .withArgs(DID_HASH);
  });

  it('supports suspend -> reinstate and permanent revoke', async () => {
    const { registry, governor, controller } = await loadFixture(withIssuerFixture);
    await registry.connect(governor).suspendIssuer(DID_HASH);
    expect(await registry.isAccredited(DID_HASH)).to.equal(false);
    expect(await registry.canRevoke(DID_HASH, controller.address)).to.equal(true);
    expect(await registry.isActiveController(DID_HASH, controller.address)).to.equal(false);

    await registry.connect(governor).reinstateIssuer(DID_HASH);
    expect(await registry.isAccredited(DID_HASH)).to.equal(true);

    await registry.connect(governor).revokeIssuer(DID_HASH);
    expect(await registry.isAccredited(DID_HASH)).to.equal(false);
    expect(await registry.canRevoke(DID_HASH, controller.address)).to.equal(false);
    await expect(registry.connect(governor).reinstateIssuer(DID_HASH))
      .to.be.revertedWithCustomError(registry, 'InvalidStatusTransition')
      .withArgs(Status.Revoked, Status.Active);
    await expect(registry.connect(governor).revokeIssuer(DID_HASH)).to.be.revertedWithCustomError(
      registry,
      'InvalidStatusTransition',
    );
  });

  it('reverts for unknown issuers', async () => {
    const { registry, governor } = await loadFixture(deployFixture);
    await expect(registry.connect(governor).suspendIssuer(DID_HASH))
      .to.be.revertedWithCustomError(registry, 'IssuerNotFound')
      .withArgs(DID_HASH);
  });

  it('only lets governors rotate controllers', async () => {
    const { registry, governor, controller, newController } = await loadFixture(withIssuerFixture);
    await expect(registry.connect(controller).rotateController(DID_HASH, newController.address)).to.be.revertedWithCustomError(
      registry,
      'AccessControlUnauthorizedAccount',
    );
    await expect(registry.connect(governor).rotateController(DID_HASH, newController.address))
      .to.emit(registry, 'ControllerRotated')
      .withArgs(DID_HASH, controller.address, newController.address);
    expect(await registry.isActiveController(DID_HASH, newController.address)).to.equal(true);
    expect(await registry.isActiveController(DID_HASH, controller.address)).to.equal(false);
  });

  it('lets the controller or a governor update metadata', async () => {
    const { registry, controller, other } = await loadFixture(withIssuerFixture);
    await expect(registry.connect(controller).updateMetadata(DID_HASH, 'ipfs://v2'))
      .to.emit(registry, 'IssuerMetadataUpdated')
      .withArgs(DID_HASH, 'ipfs://v2');
    expect((await registry.getIssuer(DID_HASH)).metadataURI).to.equal('ipfs://v2');
    await expect(registry.connect(other).updateMetadata(DID_HASH, 'x')).to.be.revertedWithCustomError(
      registry,
      'NotAuthorized',
    );
  });

  it('manages schemas', async () => {
    const { registry, governor } = await loadFixture(withIssuerFixture);
    const h = ethers.id(VCT);
    expect(await registry.isSchemaRegistered(h)).to.equal(true);
    await expect(registry.connect(governor).registerSchema(h, VCT)).to.be.revertedWithCustomError(
      registry,
      'SchemaAlreadyRegistered',
    );
    await expect(registry.connect(governor).deprecateSchema(h)).to.emit(registry, 'SchemaDeprecated').withArgs(h);
    expect(await registry.isSchemaRegistered(h)).to.equal(false);
    await expect(registry.connect(governor).deprecateSchema(ethers.id('nope'))).to.be.revertedWithCustomError(
      registry,
      'SchemaNotFound',
    );
  });

  it('can be paused by the pauser only', async () => {
    const { registry, admin, governor, controller, other } = await loadFixture(deployFixture);
    await expect(registry.connect(other).pause()).to.be.revertedWithCustomError(registry, 'AccessControlUnauthorizedAccount');
    await registry.connect(admin).pause();
    await expect(registry.connect(governor).registerIssuer(DID, controller.address, '')).to.be.revertedWithCustomError(
      registry,
      'EnforcedPause',
    );
    await registry.connect(admin).unpause();
    await registry.connect(governor).registerIssuer(DID, controller.address, '');
  });
});

describe('RevocationRegistry', () => {
  it('lets only the issuer controller revoke', async () => {
    const { revocation, controller, other } = await loadFixture(withIssuerFixture);
    await expect(revocation.connect(other).revoke(DID_HASH, 5))
      .to.be.revertedWithCustomError(revocation, 'NotIssuerController')
      .withArgs(DID_HASH, other.address);
    await expect(revocation.connect(controller).revoke(DID_HASH, 5))
      .to.emit(revocation, 'CredentialRevoked')
      .withArgs(DID_HASH, 5, controller.address);
    expect(await revocation.isRevoked(DID_HASH, 5)).to.equal(true);
    expect(await revocation.isRevoked(DID_HASH, 4)).to.equal(false);
    expect(await revocation.isRevoked(DID_HASH, 6)).to.equal(false);
  });

  it('packs bits across word boundaries', async () => {
    const { revocation, controller } = await loadFixture(withIssuerFixture);
    const indices = [0, 255, 256, 511, 1_048_575];
    await revocation.connect(controller).revokeBatch(DID_HASH, indices);
    for (const i of indices) expect(await revocation.isRevoked(DID_HASH, i)).to.equal(true);
    expect(await revocation.isRevoked(DID_HASH, 1)).to.equal(false);
    expect(await revocation.isRevoked(DID_HASH, 257)).to.equal(false);
    expect(await revocation.getWord(DID_HASH, 0)).to.equal((1n << 255n) | 1n);
    expect(await revocation.getWord(DID_HASH, 1)).to.equal((1n << 255n) | 1n);
    expect([...(await revocation.isRevokedBatch(DID_HASH, [0, 1, 256]))]).to.deep.equal([true, false, true]);
    const words = await revocation.getWords(DID_HASH, 0, 2);
    expect(words.length).to.equal(2);
    expect(await revocation.revokedCount(DID_HASH)).to.equal(BigInt(indices.length));
  });

  it('is idempotent', async () => {
    const { revocation, controller } = await loadFixture(withIssuerFixture);
    await revocation.connect(controller).revoke(DID_HASH, 9);
    await expect(revocation.connect(controller).revoke(DID_HASH, 9)).not.to.emit(revocation, 'CredentialRevoked');
    expect(await revocation.revokedCount(DID_HASH)).to.equal(1n);
  });

  it('validates batch sizes', async () => {
    const { revocation, controller } = await loadFixture(withIssuerFixture);
    await expect(revocation.connect(controller).revokeBatch(DID_HASH, [])).to.be.revertedWithCustomError(revocation, 'EmptyBatch');
    const tooMany = Array.from({ length: 513 }, (_, i) => i);
    await expect(revocation.connect(controller).revokeBatch(DID_HASH, tooMany))
      .to.be.revertedWithCustomError(revocation, 'BatchTooLarge')
      .withArgs(513, 512);
  });

  it('still allows revocation while the issuer is suspended or the registry is paused', async () => {
    const { registry, revocation, admin, governor, controller } = await loadFixture(withIssuerFixture);
    await registry.connect(governor).suspendIssuer(DID_HASH);
    await registry.connect(admin).pause();
    await revocation.connect(controller).revoke(DID_HASH, 1);
    expect(await revocation.isRevoked(DID_HASH, 1)).to.equal(true);
  });

  it('isolates issuers from each other', async () => {
    const { registry, revocation, governor, controller, other } = await loadFixture(withIssuerFixture);
    const otherDid = ethers.id('did:web:college-b.example');
    await registry.connect(governor).registerIssuer('did:web:college-b.example', other.address, '');
    await revocation.connect(controller).revoke(DID_HASH, 7);
    expect(await revocation.isRevoked(otherDid, 7)).to.equal(false);
    await expect(revocation.connect(controller).revoke(otherDid, 7)).to.be.revertedWithCustomError(
      revocation,
      'NotIssuerController',
    );
  });
});

describe('MerkleAnchor', () => {
  function buildTree() {
    const jwts = ['jwt-1', 'jwt-2', 'jwt-3'].map((j) => ethers.id(j));
    return { jwts, tree: StandardMerkleTree.of(jwts.map((v) => [v]), ['bytes32']) };
  }

  it('anchors a batch root and verifies inclusion', async () => {
    const { anchor, controller } = await loadFixture(withIssuerFixture);
    const { jwts, tree } = buildTree();
    await expect(anchor.connect(controller).anchorBatch(DID_HASH, tree.root, jwts.length))
      .to.emit(anchor, 'BatchAnchored')
      .withArgs(DID_HASH, tree.root, jwts.length, anyValue);
    expect(await anchor.anchoredAt(DID_HASH, tree.root)).to.equal(BigInt(await time.latest()));
    expect(await anchor.batchCount(DID_HASH)).to.equal(1n);
    const batch = await anchor.getBatch(DID_HASH, tree.root);
    expect(batch.leafCount).to.equal(3n);

    for (let i = 0; i < jwts.length; i++) {
      const leaf = tree.leafHash([jwts[i]]);
      expect(await anchor.verifyInclusion(DID_HASH, tree.root, leaf, tree.getProof(i))).to.equal(true);
    }
    const fakeLeaf = tree.leafHash([ethers.id('forged')]);
    expect(await anchor.verifyInclusion(DID_HASH, tree.root, fakeLeaf, tree.getProof(0))).to.equal(false);
  });

  it('returns false for unanchored roots', async () => {
    const { anchor } = await loadFixture(withIssuerFixture);
    const { jwts, tree } = buildTree();
    expect(await anchor.verifyInclusion(DID_HASH, tree.root, tree.leafHash([jwts[0]]), tree.getProof(0))).to.equal(false);
  });

  it('enforces access control and input validation', async () => {
    const { registry, anchor, admin, governor, controller, other } = await loadFixture(withIssuerFixture);
    const { tree } = buildTree();
    await expect(anchor.connect(other).anchorBatch(DID_HASH, tree.root, 3)).to.be.revertedWithCustomError(
      anchor,
      'NotIssuerController',
    );
    await expect(anchor.connect(controller).anchorBatch(DID_HASH, ethers.ZeroHash, 3)).to.be.revertedWithCustomError(
      anchor,
      'ZeroRoot',
    );
    await expect(anchor.connect(controller).anchorBatch(DID_HASH, tree.root, 0)).to.be.revertedWithCustomError(
      anchor,
      'InvalidLeafCount',
    );
    await anchor.connect(controller).anchorBatch(DID_HASH, tree.root, 3);
    await expect(anchor.connect(controller).anchorBatch(DID_HASH, tree.root, 3))
      .to.be.revertedWithCustomError(anchor, 'AlreadyAnchored')
      .withArgs(tree.root);

    await registry.connect(governor).suspendIssuer(DID_HASH);
    await expect(anchor.connect(controller).anchorBatch(DID_HASH, ethers.id('r2'), 1)).to.be.revertedWithCustomError(
      anchor,
      'NotIssuerController',
    );
    await registry.connect(governor).reinstateIssuer(DID_HASH);
    await registry.connect(admin).pause();
    await expect(anchor.connect(controller).anchorBatch(DID_HASH, ethers.id('r2'), 1)).to.be.revertedWithCustomError(
      anchor,
      'RegistryPaused',
    );
  });
});
