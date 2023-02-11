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

#[derive(Default, Debug, Serialize, Deserialize, PartialEq)]
pub struct MollieErrorResponse {
    pub status: i16,
    pub title: String,
    pub detail: String,
}