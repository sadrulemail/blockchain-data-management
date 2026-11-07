// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {QualityLedger} from "../src/QualityLedger.sol";
import {IDataRegistry} from "../src/interfaces/IDataRegistry.sol";
import {BaseTest} from "./Base.t.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

contract QualityLedgerTest is BaseTest {
    bytes32 internal constant REPORT = keccak256("quality-report");
    string internal constant REPORT_URI = "dl://documents/7d1a";

    uint256 internal datasetId;

    function setUp() public override {
        super.setUp();
        datasetId = _register(IDataRegistry.Classification.Internal);
        _commit(datasetId);
    }

    function test_Attest_StoresAndEmits() public {
        vm.expectEmit(address(quality));
        emit QualityLedger.QualityAttested(datasetId, 1, auditor, 9650, true, REPORT, REPORT_URI);
        vm.prank(auditor);
        quality.attest(datasetId, 1, 9650, true, REPORT, REPORT_URI);

        assertEq(quality.attestationCount(datasetId, 1), 1);
        assertTrue(quality.hasAttested(datasetId, 1, auditor));
        QualityLedger.Attestation memory a = quality.getAttestation(datasetId, 1, 0);
        assertEq(a.auditor, auditor);
        assertEq(a.scoreBps, 9650);
        assertTrue(a.passed);
        assertEq(a.reportHash, REPORT);
        assertEq(a.reportURI, REPORT_URI);
        assertEq(a.attestedAt, block.timestamp);
    }

    function test_Attest_OnlyAuditor() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, owner, quality.AUDITOR_ROLE()
            )
        );
        vm.prank(owner);
        quality.attest(datasetId, 1, 10_000, true, REPORT, REPORT_URI);
    }

    function test_Attest_OncePerAuditorAndVersion() public {
        vm.prank(auditor);
        quality.attest(datasetId, 1, 10_000, true, REPORT, REPORT_URI);
        vm.expectRevert(abi.encodeWithSelector(QualityLedger.AlreadyAttested.selector, datasetId, 1, auditor));
        vm.prank(auditor);
        quality.attest(datasetId, 1, 9000, true, REPORT, REPORT_URI);
    }

    function test_Attest_RejectsConflictOfInterest() public {
        vm.prank(owner);
        registry.setSteward(datasetId, auditor, true);
        vm.expectRevert(abi.encodeWithSelector(QualityLedger.ConflictOfInterest.selector, datasetId, auditor));
        vm.prank(auditor);
        quality.attest(datasetId, 1, 10_000, true, REPORT, REPORT_URI);
    }

    function test_Attest_RejectsUnknownAndWithdrawnVersions() public {
        vm.expectRevert(abi.encodeWithSelector(QualityLedger.VersionNotAttestable.selector, datasetId, 2));
        vm.prank(auditor);
        quality.attest(datasetId, 2, 10_000, true, REPORT, REPORT_URI);

        vm.prank(owner);
        registry.setVersionStatus(datasetId, 1, IDataRegistry.VersionStatus.Withdrawn, "faulty extract");
        vm.expectRevert(abi.encodeWithSelector(QualityLedger.VersionNotAttestable.selector, datasetId, 1));
        vm.prank(auditor);
        quality.attest(datasetId, 1, 10_000, true, REPORT, REPORT_URI);
    }

    function test_Attest_RejectsBadInput() public {
        vm.startPrank(auditor);
        vm.expectRevert(abi.encodeWithSelector(QualityLedger.InvalidScore.selector, 10_001));
        quality.attest(datasetId, 1, 10_001, true, REPORT, REPORT_URI);
        vm.expectRevert(QualityLedger.InvalidHash.selector);
        quality.attest(datasetId, 1, 10_000, true, bytes32(0), REPORT_URI);
        vm.stopPrank();
    }

    function test_QualitySummary_AggregatesAuditors() public {
        (uint256 count, uint256 passed, uint16 minScore) = quality.qualitySummary(datasetId, 1);
        assertEq(count, 0);
        assertEq(passed, 0);
        assertEq(minScore, 0);

        address second = makeAddr("second-auditor");
        vm.startPrank(admin);
        quality.grantRole(quality.AUDITOR_ROLE(), second);
        vm.stopPrank();

        vm.prank(auditor);
        quality.attest(datasetId, 1, 9800, true, REPORT, REPORT_URI);
        vm.prank(second);
        quality.attest(datasetId, 1, 7250, false, keccak256("second"), "dl://documents/2");

        (count, passed, minScore) = quality.qualitySummary(datasetId, 1);
        assertEq(count, 2);
        assertEq(passed, 1);
        assertEq(minScore, 7250);
    }

    function test_GetAttestation_RevertsOutOfRange() public {
        vm.expectRevert(abi.encodeWithSelector(QualityLedger.UnknownAttestation.selector, datasetId, 1, 0));
        quality.getAttestation(datasetId, 1, 0);
    }

    function test_Constructor_RevertsOnZeroAddresses() public {
        vm.expectRevert(QualityLedger.InvalidAccount.selector);
        new QualityLedger(IDataRegistry(address(0)), admin);
    }
}
