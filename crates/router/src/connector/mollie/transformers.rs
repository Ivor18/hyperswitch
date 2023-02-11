use base64::Engine;
use error_stack::{IntoReport, ResultExt};
use serde::{Deserialize, Serialize};

use crate::{
    connector::utils::AccessTokenRequestInfo,
    consts,
    core::errors,
    pii::{self, Secret},
    types::{self, api, storage::enums},
    utils::OptionExt,
};

const WALLET_IDENTIFIER: &str = "PBL";

#[derive(Debug, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MolliePaymentsRequest {
    amount: MolliePaymentAmount,
    description: String,
    redirect_url: String,
    cancel_url: Option<String>,
    webhook_url: Option<String>,
    locale: Option<String>,
    method: Option<String>,
    restrict_payment_methods_to_country: Option<String>,
    metadata: Option<serde_json::Value>,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MolliePaymentMethod {
    pay_method: MolliePaymentMethodData,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MolliePaymentAmount {
    currency: String,
    value: String
}

#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum MolliePaymentMethodData {
    Card(MollieCard),
    Wallet(MollieWallet),
}

#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum MollieCard {
    #[serde(rename_all = "camelCase")]
    Card {
        number: Secret<String, pii::CardNumber>,
        expiration_month: Secret<String>,
        expiration_year: Secret<String>,
        cvv: Secret<String>,
    },
}

#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MollieWallet {
    pub value: MollieWalletCode,
    #[serde(rename = "type")]
    pub wallet_type: String,
    pub authorization_code: String,
}
#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum MollieWalletCode {
    Ap,
    Jp,
}

impl TryFrom<&types::PaymentsAuthorizeRouterData> for MolliePaymentsRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &types::PaymentsAuthorizeRouterData) -> Result<Self, Self::Error> {
        let auth_type = MollieAuthType::try_from(&item.connector_auth_type)?;
        let payment_method = match item.request.payment_method_data.clone() {
            api::PaymentMethod::Card(ccard) => Ok(MolliePaymentMethod {
                pay_method: MolliePaymentMethodData::Card(MollieCard::Card {
                    number: ccard.card_number,
                    expiration_month: ccard.card_exp_month,
                    expiration_year: ccard.card_exp_year,
                    cvv: ccard.card_cvc,
                }),
            }),
            api::PaymentMethod::Wallet(wallet_data) => match wallet_data.issuer_name {
                api_models::enums::WalletIssuer::GooglePay => Ok(MolliePaymentMethod {
                    pay_method: MolliePaymentMethodData::Wallet({
                        MollieWallet {
                            value: MollieWalletCode::Ap,
                            wallet_type: WALLET_IDENTIFIER.to_string(),
                            authorization_code: consts::BASE64_ENGINE.encode(
                                wallet_data
                                    .token
                                    .get_required_value("token")
                                    .change_context(errors::ConnectorError::RequestEncodingFailed)
                                    .attach_printable("No token passed")?,
                            ),
                        }
                    }),
                }),
                api_models::enums::WalletIssuer::ApplePay => Ok(MolliePaymentMethod {
                    pay_method: MolliePaymentMethodData::Wallet({
                        MollieWallet {
                            value: MollieWalletCode::Jp,
                            wallet_type: WALLET_IDENTIFIER.to_string(),
                            authorization_code: consts::BASE64_ENGINE.encode(
                                wallet_data
                                    .token
                                    .get_required_value("token")
                                    .change_context(errors::ConnectorError::RequestEncodingFailed)
                                    .attach_printable("No token passed")?,
                            ),
                        }
                    }),
                }),
                _ => Err(errors::ConnectorError::NotImplemented(
                    "Unknown Wallet in Payment Method".to_string(),
                )),
            },
            _ => Err(errors::ConnectorError::NotImplemented(
                "Unknown payment method".to_string(),
            )),
        }?;

        let amount_info = MolliePaymentAmount {
            value: format!("{}.00", item.request.amount.to_string()),
            currency: item.request.currency.to_string(),
        };

        Ok(Self {
            amount: amount_info,
            description: item.description.clone().ok_or(
                errors::ConnectorError::MissingRequiredField {
                    field_name: "item.description",
                },
            )?,
            redirect_url: item.return_url.clone().ok_or(
                errors::ConnectorError::MissingRequiredField {
                    field_name: "item.return_url",
                },
            )?,
            cancel_url: None,
            webhook_url: None,
            locale: None,
            method: None,
            restrict_payment_methods_to_country: None,
            metadata: None,
        })
    }
}

pub struct MollieAuthType {
    pub(super) api_key: String,
}

impl TryFrom<&types::ConnectorAuthType> for MollieAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(auth_type: &types::ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            types::ConnectorAuthType::HeaderKey { api_key } => Ok(Self {
                api_key: api_key.to_string(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType)?,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum MolliePaymentStatus {
    #[default]
    Open,
    Canceled,
    Pending,
    Authorized,
    Expired,
    Failed,
    Paid
}

impl From<MolliePaymentStatus> for enums::AttemptStatus {
    fn from(item: MolliePaymentStatus) -> Self {
        match item {
            MolliePaymentStatus::Open => Self::Started,
            MolliePaymentStatus::Canceled => Self::Voided,
            MolliePaymentStatus::Pending => Self::Pending,
            MolliePaymentStatus::Authorized => Self::Authorized,
            MolliePaymentStatus::Expired => Self::AuthorizationFailed,
            MolliePaymentStatus::Failed => Self::Failure,
            MolliePaymentStatus::Paid => Self::Charged,
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MolliePaymentsResponse {
    pub id: String,
    pub status: MolliePaymentStatus
}

impl<F, T>
    TryFrom<types::ResponseRouterData<F, MolliePaymentsResponse, T, types::PaymentsResponseData>>
    for types::RouterData<F, T, types::PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: types::ResponseRouterData<F, MolliePaymentsResponse, T, types::PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            status: enums::AttemptStatus::from(item.response.status),
            response: Ok(types::PaymentsResponseData::TransactionResponse {
                resource_id: types::ResponseId::ConnectorTransactionId(item.response.id),
                redirect: true,
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
            }),
            amount_captured: None,
            ..item.data
        })
    }
}

#[derive(Default, Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MolliePaymentsCaptureRequest {
    order_id: String,
    order_status: OrderStatus,
}

impl TryFrom<&types::PaymentsCaptureRouterData> for MolliePaymentsCaptureRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &types::PaymentsCaptureRouterData) -> Result<Self, Self::Error> {
        Ok(Self {
            order_id: item.request.connector_transaction_id.clone(),
            order_status: OrderStatus::Completed,
        })
    }
}

#[derive(Default, Debug, Clone, Deserialize, PartialEq)]
pub struct MolliePaymentsCaptureResponse {
    status: MolliePaymentStatusData,
}

impl<F, T>
    TryFrom<
        types::ResponseRouterData<F, MolliePaymentsCaptureResponse, T, types::PaymentsResponseData>,
    > for types::RouterData<F, T, types::PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: types::ResponseRouterData<
            F,
            MolliePaymentsCaptureResponse,
            T,
            types::PaymentsResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            status: enums::AttemptStatus::from(item.response.status.status_code.clone()),
            response: Ok(types::PaymentsResponseData::TransactionResponse {
                resource_id: types::ResponseId::NoResponseId,
                redirect: false,
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
            }),
            amount_captured: None,
            ..item.data
        })
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct MollieAuthUpdateRequest {
    grant_type: String,
    client_id: String,
    client_secret: String,
}

impl TryFrom<&types::RefreshTokenRouterData> for MollieAuthUpdateRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &types::RefreshTokenRouterData) -> Result<Self, Self::Error> {
        Ok(Self {
            grant_type: "client_credentials".to_string(),
            client_id: item.get_request_id()?,
            client_secret: item.request.app_id.clone(),
        })
    }
}
#[derive(Default, Debug, Clone, Deserialize, PartialEq)]
pub struct MollieAuthUpdateResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub grant_type: String,
}

impl<F, T> TryFrom<types::ResponseRouterData<F, MollieAuthUpdateResponse, T, types::AccessToken>>
    for types::RouterData<F, T, types::AccessToken>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: types::ResponseRouterData<F, MollieAuthUpdateResponse, T, types::AccessToken>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(types::AccessToken {
                token: item.response.access_token,
                expires: item.response.expires_in,
            }),
            ..item.data
        })
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MolliePaymentsCancelResponse {
    pub order_id: String,
    pub ext_order_id: Option<String>,
    pub status: MolliePaymentStatusData,
}

impl<F, T>
    TryFrom<
        types::ResponseRouterData<F, MolliePaymentsCancelResponse, T, types::PaymentsResponseData>,
    > for types::RouterData<F, T, types::PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: types::ResponseRouterData<
            F,
            MolliePaymentsCancelResponse,
            T,
            types::PaymentsResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            status: enums::AttemptStatus::from(item.response.status.status_code.clone()),
            response: Ok(types::PaymentsResponseData::TransactionResponse {
                resource_id: types::ResponseId::ConnectorTransactionId(item.response.order_id),
                redirect: false,
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
            }),
            amount_captured: None,
            ..item.data
        })
    }
}

#[allow(dead_code)]
#[derive(Debug, Serialize, Eq, PartialEq, Default, Deserialize, Clone)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OrderStatus {
    New,
    Canceled,
    Completed,
    WaitingForConfirmation,
    #[default]
    Pending,
}

impl From<OrderStatus> for enums::AttemptStatus {
    fn from(item: OrderStatus) -> Self {
        match item {
            OrderStatus::New => Self::PaymentMethodAwaited,
            OrderStatus::Canceled => Self::Voided,
            OrderStatus::Completed => Self::Charged,
            OrderStatus::Pending => Self::Pending,
            OrderStatus::WaitingForConfirmation => Self::Authorized,
        }
    }
}

#[derive(Debug, Serialize, Default, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MolliePaymentStatusData {
    status_code: MolliePaymentStatus,
    severity: Option<String>,
    status_desc: Option<String>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MollieProductData {
    name: String,
    unit_price: String,
    quantity: String,
    #[serde(rename = "virtual")]
    virtually: Option<bool>,
    listing_date: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MollieOrderResponseData {
    order_id: String,
    ext_order_id: Option<String>,
    order_create_date: String,
    notify_url: Option<String>,
    customer_ip: std::net::IpAddr,
    merchant_pos_id: String,
    description: String,
    validity_time: Option<String>,
    currency_code: enums::Currency,
    total_amount: String,
    buyer: Option<MollieOrderResponseBuyerData>,
    pay_method: Option<MollieOrderResponsePayMethod>,
    products: Option<Vec<MollieProductData>>,
    status: OrderStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MollieOrderResponseBuyerData {
    ext_customer_id: Option<String>,
    email: Option<String>,
    phone: Option<String>,
    first_name: Option<String>,
    last_name: Option<String>,
    #[serde(rename = "nin")]
    national_identification_number: Option<String>,
    language: Option<String>,
    delivery: Option<String>,
    customer_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MollieOrderResponsePayMethod {
    CardToken,
    Pbl,
    Installemnts,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MollieOrderResponseProperty {
    name: String,
    value: String,
}

#[derive(Default, Debug, Clone, Deserialize, PartialEq)]
pub struct MolliePaymentsSyncResponse {
    orders: Vec<MollieOrderResponseData>,
    status: MolliePaymentStatusData,
    properties: Option<Vec<MollieOrderResponseProperty>>,
}

impl<F, T>
    TryFrom<types::ResponseRouterData<F, MolliePaymentsSyncResponse, T, types::PaymentsResponseData>>
    for types::RouterData<F, T, types::PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: types::ResponseRouterData<
            F,
            MolliePaymentsSyncResponse,
            T,
            types::PaymentsResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        let order = match item.response.orders.first() {
            Some(order) => order,
            _ => Err(errors::ConnectorError::ResponseHandlingFailed)?,
        };
        Ok(Self {
            status: enums::AttemptStatus::from(order.status.clone()),
            response: Ok(types::PaymentsResponseData::TransactionResponse {
                resource_id: types::ResponseId::ConnectorTransactionId(order.order_id.clone()),
                redirect: false,
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
            }),
            amount_captured: Some(
                order
                    .total_amount
                    .parse::<i64>()
                    .into_report()
                    .change_context(errors::ConnectorError::ResponseDeserializationFailed)?,
            ),
            ..item.data
        })
    }
}

#[derive(Default, Debug, Eq, PartialEq, Serialize)]
pub struct MollieRefundRequestData {
    description: String,
    amount: Option<i64>,
}

#[derive(Default, Debug, Serialize)]
pub struct MollieRefundRequest {
    refund: MollieRefundRequestData,
}

impl<F> TryFrom<&types::RefundsRouterData<F>> for MollieRefundRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &types::RefundsRouterData<F>) -> Result<Self, Self::Error> {
        Ok(Self {
            refund: MollieRefundRequestData {
                description: item.request.reason.clone().ok_or(
                    errors::ConnectorError::MissingRequiredField {
                        field_name: "item.request.reason",
                    },
                )?,
                amount: None,
            },
        })
    }
}

// Type definition for Refund Response

#[allow(dead_code)]
#[derive(Debug, Serialize, Eq, PartialEq, Default, Deserialize, Clone)]
#[serde(rename_all = "UPPERCASE")]
pub enum RefundStatus {
    Finalized,
    Completed,
    Canceled,
    #[default]
    Pending,
}

impl From<RefundStatus> for enums::RefundStatus {
    fn from(item: RefundStatus) -> Self {
        match item {
            RefundStatus::Finalized | RefundStatus::Completed => Self::Success,
            RefundStatus::Canceled => Self::Failure,
            RefundStatus::Pending => Self::Pending,
        }
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MollieRefundResponseData {
    refund_id: String,
    ext_refund_id: String,
    amount: String,
    currency_code: enums::Currency,
    description: String,
    creation_date_time: String,
    status: RefundStatus,
    status_date_time: Option<String>,
}

#[derive(Default, Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefundResponse {
    refund: MollieRefundResponseData,
}

impl TryFrom<types::RefundsResponseRouterData<api::Execute, RefundResponse>>
    for types::RefundsRouterData<api::Execute>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: types::RefundsResponseRouterData<api::Execute, RefundResponse>,
    ) -> Result<Self, Self::Error> {
        let refund_status = enums::RefundStatus::from(item.response.refund.status);
        Ok(Self {
            response: Ok(types::RefundsResponseData {
                connector_refund_id: item.response.refund.refund_id,
                refund_status,
            }),
            ..item.data
        })
    }
}

#[derive(Default, Debug, Clone, Deserialize)]
pub struct RefundSyncResponse {
    refunds: Vec<MollieRefundResponseData>,
}
impl TryFrom<types::RefundsResponseRouterData<api::RSync, RefundSyncResponse>>
    for types::RefundsRouterData<api::RSync>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: types::RefundsResponseRouterData<api::RSync, RefundSyncResponse>,
    ) -> Result<Self, Self::Error> {
        let refund = match item.response.refunds.first() {
            Some(refund) => refund,
            _ => Err(errors::ConnectorError::ResponseHandlingFailed)?,
        };
        Ok(Self {
            response: Ok(types::RefundsResponseData {
                connector_refund_id: refund.refund_id.clone(),
                refund_status: enums::RefundStatus::from(refund.status.clone()),
            }),
            ..item.data
        })
    }
}

#[derive(Default, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MollieErrorData {
    pub status_code: String,
    pub code: Option<String>,
    pub code_literal: Option<String>,
    pub status_desc: String,
}
#[derive(Default, Debug, Serialize, Deserialize, PartialEq)]
pub struct MollieErrorResponse {
    pub status: i16,
    pub title: String,
    pub detail: String,
}

#[derive(Deserialize, Debug)]
pub struct MollieAccessTokenErrorResponse {
    pub error: String,
    pub error_description: String,
}
