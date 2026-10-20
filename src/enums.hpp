// The subset of ASHRAE 135 enumerations this stack uses.
#pragma once
#include <cstdint>

namespace bac {

enum ObjectType : uint16_t {
    kAnalogInput = 0, kAnalogOutput = 1, kAnalogValue = 2,
    kBinaryInput = 3, kBinaryOutput = 4, kBinaryValue = 5, kDevice = 8,
};

enum PropertyId : uint32_t {
    kPropAll = 8, kPropOptional = 80, kPropRequired = 105,
    kPropApduTimeout = 11, kPropAppSoftwareVersion = 12, kPropCovIncrement = 22,
    kPropDescription = 28, kPropDeviceAddressBinding = 30, kPropEventState = 36,
    kPropFirmwareRevision = 44, kPropMaxApduLength = 62, kPropModelName = 70,
    kPropNumberOfApduRetries = 73, kPropObjectIdentifier = 75, kPropObjectList = 76,
    kPropObjectName = 77, kPropObjectType = 79, kPropOutOfService = 81, kPropPresentValue = 85,
    kPropPriorityArray = 87, kPropProtocolObjectTypesSupported = 96,
    kPropProtocolServicesSupported = 97, kPropProtocolVersion = 98, kPropRelinquishDefault = 104,
    kPropSegmentationSupported = 107, kPropStatusFlags = 111, kPropSystemStatus = 112,
    kPropUnits = 117, kPropVendorIdentifier = 120, kPropVendorName = 121,
    kPropProtocolRevision = 139, kPropDatabaseRevision = 155, kPropPropertyList = 371,
};

enum ConfirmedService : uint8_t {
    kSvcConfirmedCovNotification = 1, kSvcSubscribeCov = 5, kSvcReadProperty = 12,
    kSvcReadPropertyMultiple = 14, kSvcWriteProperty = 15,
};
enum UnconfirmedService : uint8_t {
    kSvcIAm = 0, kSvcUnconfirmedCovNotification = 2, kSvcWhoIs = 8,
};

enum PduType : uint8_t {
    kPduConfirmedRequest = 0, kPduUnconfirmedRequest = 1, kPduSimpleAck = 2, kPduComplexAck = 3,
    kPduSegmentAck = 4, kPduError = 5, kPduReject = 6, kPduAbort = 7,
};

enum ErrorClass : uint32_t { kErrClassDevice = 0, kErrClassObject = 1, kErrClassProperty = 2, kErrClassResources = 3, kErrClassServices = 5 };
enum ErrorCode : uint32_t {
    kErrOther = 0, kErrInvalidDataType = 9, kErrServiceRequestDenied = 29, kErrUnknownObject = 31,
    kErrUnknownProperty = 32, kErrValueOutOfRange = 37, kErrWriteAccessDenied = 40,
    kErrInvalidArrayIndex = 42, kErrCovSubscriptionFailed = 43, kErrPropertyIsNotAnArray = 50,
};
enum RejectReason : uint8_t {
    kRejectOther = 0, kRejectInvalidTag = 4, kRejectMissingRequiredParameter = 5,
    kRejectParameterOutOfRange = 6, kRejectUnrecognizedService = 9,
};
enum AbortReason : uint8_t { kAbortOther = 0, kAbortBufferOverflow = 1, kAbortSegmentationNotSupported = 4 };

enum EngineeringUnits : uint32_t { kUnitsDegreesCelsius = 62, kUnitsNoUnits = 95, kUnitsPercent = 98 };

constexpr uint16_t kBacnetPort = 47808;  // 0xBAC0
constexpr uint32_t kVendorId = 999;      // placeholder: this demo has no ASHRAE-assigned vendor id

}  // namespace bac
