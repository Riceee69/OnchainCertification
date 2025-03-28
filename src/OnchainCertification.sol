// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC721URIStorage, ERC721} from "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";

/**
 * @title Certification
 * @dev Smart contract that handles student registration, exam validation, and certification issuance
 */
contract OnchainCertification is ERC721URIStorage, AccessControl, EIP712 {
    //////////////////////////////////////////////////////////
    // ERRORS
    //////////////////////////////////////////////////////////
    error StudentAlreadyRegistered(bytes studentId);
    error StudentNotRegistered();
    error InvalidCertificationId(uint256 certificationId);
    error InvalidSignature();
    error NotValidator();
    error InvalidStudentId(bytes studentId);
    error InvalidExamId(uint256 examId);
    error ExamInactive();
    error NotQualifiedForCertification();
    error ExamExpired();
    error ExamAlreadyRegistered();
    error InvalidCertificationUpdate();
    error SoulboundTokenCannotBeTransferred();

    /////////////////////////////////////////////////////////
    // TYPE DECLARATIONS
    /////////////////////////////////////////////////////////
    struct Student {
        bytes studentId;
        address studentAddress;
        string name;
        bool isRegistered;
        mapping(uint256 certificationId => bool) certifications;
    }

    struct Certification {
        uint256 certificationId;
        string certificationName;
        uint256 validityPeriod;
    }

    struct Exam {
        uint256 examId;
        uint256 certificationId;
        bool isActive;
        uint256 validityPeriod;
    }

    //EIP712 signature struct
    struct ValidateExam {
        bytes studentId;
        uint256 examId;
        bool passed;
    }

    struct StudentCertificates{
        uint256 certId;
        string certName;
        uint256 validity;
        string studentName;
    }

    using Strings for uint256;
    //////////////////////////////////////////////////////////
    // STATE VARIABLES
    //////////////////////////////////////////////////////////
    // Role definitions

    bytes32 public constant VALIDATOR_ROLE = keccak256("VALIDATOR_ROLE");
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 private constant MESSAGE_TYPEHASH = keccak256("ValidateExam(bytes studentId, uint256 examId, bool passed)");

    uint256 private nonce;
    uint256 private _certificationIdCounter;
    uint256 private _examIdCounter;
    uint256 private _tokenIdCounter;
    string public institution;
    uint256 public immutable institutionId;

    // Mapping from address to Student
    mapping(address => Student) public _students;

    // Mapping from student ID to address
    mapping(bytes studentID => address) private _studentAddresses;

    // Mapping for all certifications
    mapping(uint256 => Certification) public _certifications;

    // Mapping for all exams
    mapping(uint256 => Exam) public _exams;

    // Mapping to check a students's registered exam
    mapping(bytes studentId => mapping(uint256 examId => bool)) public registeredForExam;

    // Mapping for each student on chain cert to the tokenID 
    mapping(uint256 => StudentCertificates) public tokenIdToAttributes;
    //////////////////////////////////////////////////////////
    // EVENTS
    //////////////////////////////////////////////////////////
    event StudentRegistered(bytes indexed studentId, address indexed studentAddress, string name);
    event ExamValidated(uint256 indexed examId, bytes indexed studentId, bool passed);
    event CertificationIssued(uint256 indexed certificationId, bytes indexed studentId, uint256 tokenId);
    event CertificationURIUpdated(uint256 indexed tokenId, string newName);
    event CertificationURIUpdated(uint256 indexed tokenId, uint256 newValidity);
    event ExamDeactivated(uint256 examId);


    //////////////////////////////////////////////////////////
    // FUNCTIONS
    //////////////////////////////////////////////////////////
    constructor(string memory _institution, uint256 uuid, address _admin)
        ERC721("OnchainCertification", "OCERT")
        EIP712("OnchainCertfication", "v1.0.0")
    {
        institution = _institution;
        institutionId = uuid;

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(ADMIN_ROLE, _admin);
    }

    //////////////////////////////////////////////////////////
    // EXTERNAL/PUBLIC FUNCTIONS
    //////////////////////////////////////////////////////////
    /**
     * @dev Register a new student
     * @param _name The name of the student
     */
    function registerStudent(string calldata _name) external {
        if (_students[msg.sender].isRegistered) revert StudentAlreadyRegistered(_students[msg.sender].studentId);

        // Increment the nonce to always ensure unique student Ids
        nonce++;
        bytes memory newStudentId = abi.encodePacked(_name, block.timestamp, nonce);

        Student storage newStudent = _students[msg.sender];
        newStudent.studentId = newStudentId;
        newStudent.studentAddress = msg.sender;
        newStudent.name = _name;
        newStudent.isRegistered = true;

        _studentAddresses[newStudentId] = msg.sender;

        emit StudentRegistered(newStudentId, msg.sender, _name);
    }

    /**
     * @dev Create a new certification type
     * @param _certificationName Name of the certification
     * @param _validityPeriod the time in seconds the certification is valid for 
     */
    function createCertification(
        string calldata _certificationName,
        uint256 _validityPeriod
    ) external onlyRole(ADMIN_ROLE) {
        _certificationIdCounter++;
        uint256 newCertificationId = _certificationIdCounter;

        _certifications[newCertificationId] = Certification({
            certificationId: newCertificationId,
            certificationName: _certificationName,
            validityPeriod: block.timestamp + _validityPeriod
        });
    }

    /**
     * @dev Create a new exam for a certification
     * @param _certificationId The certification ID this exam is for
     * @param examValidityDuration The total time the exam is active for people to participate
     */
    function createExam(uint256 _certificationId, uint256 examValidityDuration) external onlyRole(ADMIN_ROLE) {
        if (_certifications[_certificationId].certificationId == 0) {
            revert InvalidCertificationId(_certificationId);
        }

        _examIdCounter++;
        uint256 newExamId = _examIdCounter;

        _exams[newExamId] = Exam({
            examId: newExamId,
            certificationId: _certificationId,
            isActive: true,
            validityPeriod: block.timestamp + examValidityDuration
        });
    }

    /**
     * @dev Allows students to register for exams
     * @param examId The ID of the exam to register for
     */
    function registerForExam(uint256 examId) external {
        if (!_students[msg.sender].isRegistered) revert StudentNotRegistered();
        if (registeredForExam[_students[msg.sender].studentId][examId]) revert ExamAlreadyRegistered();
        
        Exam memory exam = _exams[examId];
        if (exam.examId == 0) revert InvalidExamId(examId);
        if (!exam.isActive) revert ExamInactive();
        if (block.timestamp > exam.validityPeriod) revert ExamExpired();

        registeredForExam[_students[msg.sender].studentId][examId] = true;
    }

    /**
     * @dev Validate an exam result (called by validator)
     * @notice Examinee results are signed by the validators
     * @param _studentId The ID of the student who took the exam
     * @param _examId The ID of the exam taken
     * @param _passed Whether the student passed the exam
     * @param _signature Validator's signature
     */
    function validateExam(bytes calldata _studentId, uint256 _examId, bool _passed, bytes calldata _signature)
        external
    {
        address validator = _verifyValidatorSignature(_getMessageHash(_studentId, _examId, _passed), _signature);
        if (!hasRole(VALIDATOR_ROLE, validator)) revert NotValidator();

        address studentAddress = _studentAddresses[_studentId];
        if (studentAddress == address(0)) revert InvalidStudentId(_studentId);
        if(!registeredForExam[_students[msg.sender].studentId][_examId]) revert InvalidExamId(_examId);

        Exam storage exam = _exams[_examId];
        if (exam.examId == 0) revert InvalidExamId(_examId);
        if (!exam.isActive) revert ExamInactive();

        if (_passed) {
            _students[studentAddress].certifications[exam.certificationId] = true;
        }

        emit ExamValidated(_examId, _studentId, _passed);
    }

    /**
     * @dev Claim a certification NFT after passing an exam
     * @param _certificationId The ID of the certification to claim
     */
    function claimCertification(uint256 _certificationId) external {
        Student storage student = _students[msg.sender];
        if (!student.isRegistered) revert StudentNotRegistered();
        if (!student.certifications[_certificationId]) revert NotQualifiedForCertification();

        _mintCertification(student, _certificationId);

        emit CertificationIssued(_certificationId, student.studentId, _tokenIdCounter - 1);
    }

    /**
     * @dev Update the metadata URI for a certification
     * @param tokenId the NFT token for which we want to update the metadata
     * @param _certificationId The ID of the certification
     * @param _newName The new certification name
     */
    function updateCertificationName(uint256 tokenId, uint256 _certificationId, string calldata _newName) external onlyRole(ADMIN_ROLE) {
        StudentCertificates storage studentCert = tokenIdToAttributes[tokenId]; 

        if (_certificationId != studentCert.certId) revert InvalidCertificationId(_certificationId);
        if(bytes(_newName).length == 0 ) revert InvalidCertificationUpdate();   

    
        studentCert.certName = _newName;

        emit CertificationURIUpdated(tokenId, _newName);

        _setTokenURI(
            tokenId, generateTokenURI(_certificationId, studentCert.certName, studentCert.validity, studentCert.studentName, tokenId)
        );
    }

    /**
     * @dev Update the metadata URI for a certification
     * @param tokenId the NFT token for which we want to update the metadata
     * @param _certificationId The ID of the certification
     * @param _validity The new certification valid timestamp
     */
    function updateCertificationValidity(uint256 tokenId, uint256 _certificationId, uint256 _validity) external onlyRole(ADMIN_ROLE) {
        StudentCertificates storage studentCert = tokenIdToAttributes[tokenId]; 

        if (_certificationId != studentCert.certId) revert InvalidCertificationId(_certificationId);
    
        studentCert.validity = _validity;

        emit CertificationURIUpdated(tokenId, _validity);

        _setTokenURI(
            tokenId, generateTokenURI(_certificationId, studentCert.certName, studentCert.validity, studentCert.studentName, tokenId)
        );
    }

    /**
     * @dev the exam to be deactivated picked up by the off-chain process
     * @param examId The ID of the exam
     */
    function deactivateExam(uint256 examId) external onlyRole(ADMIN_ROLE) {
        _deactivateExam(examId);

        emit ExamDeactivated(examId);
    }

    //////////////////////////////////////////////////////////
    // INTERNAL/PRIVATE FUNCTIONS
    //////////////////////////////////////////////////////////
    /**
     * @dev Mint a certification NFT
     * @param _student The student receiving the certification
     * @param _certificationId The ID of the certification
     */

    function _mintCertification(Student storage _student, uint256 _certificationId) private {
        address studentAddress = _student.studentAddress;
        require(studentAddress != address(0), "Student does not exist");

        // initial default values
        Certification memory certificate = _certifications[_certificationId];
        uint256 certificateId = certificate.certificationId;
        string memory certificateName = certificate.certificationName;
        uint256 validityPeriod = certificate.validityPeriod;

        _mint(studentAddress, ++_tokenIdCounter);
        _setTokenURI(
            _tokenIdCounter, generateTokenURI(certificateId, certificateName, validityPeriod, _student.name, _tokenIdCounter)
        );
    }

    function _deactivateExam(uint256 examId) private {
        if (!_exams[examId].isActive) revert ExamInactive();
        _exams[examId].isActive = false;
    }

    //////////////////////////////////////////////////////////
    // VIEW/PURE FUNCTIONS
    //////////////////////////////////////////////////////////
    /**
     * @dev The message hash for the validator to sign
     */
    function _getMessageHash(bytes calldata _studentId, uint256 _examId, bool passed) public view returns (bytes32) {
        return _hashTypedDataV4(
            keccak256(
                abi.encode(MESSAGE_TYPEHASH, ValidateExam({studentId: _studentId, examId: _examId, passed: passed}))
            )
        );
    }

    /**
     * @dev Get the student's details
     * @param _studentId The ID of the student
     * @return studentId, studentAddress, name, isRegistered
     */
    function getStudentDetails(bytes calldata _studentId)
        external
        view
        returns (bytes memory, address, string memory, bool)
    {
        address studentAddress = _studentAddresses[_studentId];
        if (studentAddress == address(0)) revert InvalidStudentId(_studentId);

        Student storage student = _students[studentAddress];
        return (student.studentId, student.studentAddress, student.name, student.isRegistered);
    }

    /**
     * @dev Check if a student has a specific certification
     * @param _studentId The ID of the student
     * @param _certificationId The ID of the certification
     */
    function hasCertification(bytes calldata _studentId, uint256 _certificationId) external view returns (bool) {
        address studentAddress = _studentAddresses[_studentId];
        if (studentAddress == address(0)) revert InvalidStudentId(_studentId);

        return _students[studentAddress].certifications[_certificationId];
    }

    /**
     * @dev Verify a validator's signature
     * @param _dataHash The hash of the data signed
     * @param _signature The validator's signature
     * @return The address of the validator
     */
    function _verifyValidatorSignature(bytes32 _dataHash, bytes memory _signature) private pure returns (address) {
        (address validator, ECDSA.RecoverError err,) = ECDSA.tryRecover(_dataHash, _signature);
        if (err != ECDSA.RecoverError.NoError) revert InvalidSignature();
        return validator;
    }


    /**
     * @dev Generate a token URI
     * @param certificateId The ID of the certification
     * @param certificateName The name of the certification
     * @param validityPeriod The period till which this certificate is valid
     * @param studentName The name of the certified student
     * @param tokenId The token Id of the NFT certificate
     */
    function generateTokenURI(uint256 certificateId, string memory certificateName, uint256 validityPeriod, string memory studentName, uint256 tokenId)
        private
        returns (string memory)
    {


        tokenIdToAttributes[_tokenIdCounter] = StudentCertificates({
            certId: certificateId,
            certName: certificateName,
            validity: validityPeriod,
            studentName: studentName
        });

        bytes memory dataURI = abi.encodePacked(
            "{",
            '"description": "A dynamic on-chain metadata certificate",',
            '"image": "',
            generateMetadata(certificateId, certificateName, validityPeriod, studentName),
            '",',
            '"name": "OCERT#',
            tokenId.toString(),
            '"',
            "}"
        );


        return string(abi.encodePacked("data:application/json;base64,", Base64.encode(dataURI)));
    }

    /**
     * @dev Generating the SVG image for metadata
     */
    function generateMetadata(
        uint256 certificationId,
        string memory certificateName,
        uint256 validityPeriod,
        string memory studentName
    ) private pure returns (string memory) {
        // svg for on chain metadata storage 
        bytes memory svg = abi.encodePacked(
            '<svg xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMinYMin meet" viewBox="0 0 350 350">',
            "<style>.base { fill: white; font-family: serif; font-size: 14px; }</style>",
            '<rect width="100%" height="100%" fill="black" />',
            '<text x="50%" y="38%" class="base" dominant-baseline="middle" text-anchor="middle">',
            "Certificate ID: ",
            certificationId.toString(),
            "</text>",
            '<text x="50%" y="50%" class="base" dominant-baseline="middle" text-anchor="middle">',
            "Certificate Name: ",
            certificateName,
            "</text>",
            '<text x="50%" y="58%" class="base" dominant-baseline="middle" text-anchor="middle">',
            "Certificate Validity: ",
            validityPeriod.toString(),
            "</text>",
            '<text x="50%" y="74%" class="base" dominant-baseline="middle" text-anchor="middle">',
            "Student Name: ",
            studentName,
            "</text>",
            "</svg>"
        );

        return string(abi.encodePacked("data:image/svg+xml;base64,", Base64.encode(svg)));
    }

    // Override required for AccessControl and ERC721URIStorage
    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(ERC721URIStorage, AccessControl)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }

    /// @notice Override of transferFrom to prevent any transfer.
    function transferFrom(address, address, uint256) public pure override(ERC721, IERC721) {
        // Soulbound token cannot be transferred
        revert SoulboundTokenCannotBeTransferred();
    }

    function safeTransferFrom(address, address, uint256, bytes memory) public pure override(ERC721, IERC721) {
        // Soulbound token cannot be transferred
        revert SoulboundTokenCannotBeTransferred();
    }
}
