// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet.transaction

/**
 * The JSON Schemas of the four built-in transaction data types of EC TS12
 * v1.0.1 section 4.3, verbatim.
 *
 * Source: https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications
 * at `docs/technical-specifications/api/ts12-urn-eudi-sca-<type>-data-model.json`
 * (the spec text, `ts12-electronic-payments-SCA-implementation-with-wallet.md`,
 * last changed in commit 9090fe29d715d9818b0189fd60cee7f14fc5bb68, 2026-02-11;
 * files fetched from main at ee91a294c833af5188726fd8c302c641212192aa).
 * Each constant's SHA-256 is pinned in `Ts12SchemasTest`, which fails if the
 * text is edited: these are the spec's schemas, not the SDK's.
 *
 * `$schema` is JSON Schema 2020-12, in which `format` is an annotation, so
 * `date-time` / `uri` are not asserted (a date-only `execution_date`, which
 * the spec text allows, validates).
 */
internal object Ts12Schemas {

    /** `urn:eudi:sca:payment:1` (file `ts12-urn-eudi-sca-payment-1-data-model.json`), sha256 fbc788b6d39941ae969e49208ce91129dd1558ccd780175ce4a68958aa97df24. */
    const val PAYMENT: String = """{
    "${'$'}schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "properties": {
        "transaction_id": {
            "type": "string",
            "maxLength": 36,
            "minLength": 1,
            "examples": [
                "8D8AC610-566D-4EF0-9C22-186B2A5ED793"
            ]
        },
        "date_time": {
            "type": "string",
            "format": "date-time",
            "examples": [
                "2025-11-13T20:20:39+00:00"
            ]
        },
        "payee": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string"
                },
                "id": {
                    "type": "string"
                },
                "logo": {
                    "type": "string",
                    "format": "uri"
                },
                "website": {
                    "type": "string",
                    "format": "uri"
                }
            },
            "required": [
                "name",
                "id"
            ]
        },
        "pisp": {
            "type": "object",
            "properties": {
                "legal_name": {
                    "type": "string"
                },
                "brand_name": {
                    "type": "string"
                },
                "domain_name": {
                    "type": "string"
                }
            },
            "required": [
                "legal_name",
                "brand_name",
                "domain_name"
            ]
        },
        "execution_date": {
            "type": "string",
            "format": "date-time"
        },
        "currency": {
            "type": "string",
            "pattern": "^[A-Z]{3}${'$'}"
        },
        "amount": {
            "type": "number"
        },
        "amount_estimated": {
            "type": "boolean"
        },
        "amount_earmarked": {
            "type": "boolean"
        },
        "sct_inst": {
            "type": "boolean"
        },
        "recurrence": {
            "type": "object",
            "properties": {
                "start_date": {
                    "type": "string",
                    "format": "date-time"
                },
                "end_date": {
                    "type": "string",
                    "format": "date-time"
                },
                "number": {
                    "type": "integer"
                },
                "frequency": {
                    "type": "string",
                    "enum": [
                        "INDA",
                        "DAIL",
                        "WEEK",
                        "TOWK",
                        "TWMN",
                        "MNTH",
                        "TOMN",
                        "QUTR",
                        "FOMN",
                        "SEMI",
                        "YEAR",
                        "TYEA"
                    ]
                },
                "mit_options": {
                    "type": "object",
                    "properties": {
                        "amount_variable": {
                            "type": "boolean"
                        },
                        "min_amount": {
                            "type": "number"
                        },
                        "max_amount": {
                            "type": "number"
                        },
                        "total_amount": {
                            "type": "number"
                        },
                        "initial_amount": {
                            "type": "number"
                        },
                        "initial_amount_number": {
                            "type": "integer"
                        },
                        "apr": {
                            "type": "number"
                        }
                    }
                }
            },
            "required": [
                "frequency"
            ]
        }
    },
    "required": [
        "transaction_id",
        "payee",
        "currency",
        "amount"
    ],
    "additionalProperties": false
}
"""

    /** `urn:eudi:sca:login_risk_transaction:1` (file `ts12-urn-eudi-sca-login_risk_transaction-1-data-model.json`), sha256 b1ac923b1df7707fb58b35737b27bee80834c01f581a4335a805dfc33bf3ba20. */
    const val LOGIN_RISK: String = """{
    "${'$'}schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "properties": {
        "transaction_id": {
            "type": "string",
            "maxLength": 36,
            "minLength": 1,
            "examples": [
                "8D8AC610-566D-4EF0-9C22-186B2A5ED793"
            ]
        },
        "date_time": {
            "type": "string",
            "format": "date-time",
            "examples": [
                "2025-11-13T20:20:39+00:00"
            ]
        },
        "service": {
            "type": "string",
            "maxLength": 100,
            "examples": [
                "Superbank Onlinebanking"
            ]
        },
        "action": {
            "type": "string",
            "maxLength": 140,
            "examples": [
                "Login to your online account."
            ]
        }
    },
    "additionalProperties": false,
    "required": [
        "transaction_id",
        "action"
    ]
}
"""

    /** `urn:eudi:sca:account_access:1` (file `ts12-urn-eudi-sca-account_access-1-data-model.json`), sha256 b11cb79168eb9bdf64b365b2b27f815d5455833567f9b4ab3ccabc1889e94cad. */
    const val ACCOUNT_ACCESS: String = """{
    "${'$'}schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "properties": {
        "transaction_id": {
            "type": "string",
            "maxLength": 36,
            "minLength": 1,
            "examples": [
                "8D8AC610-566D-4EF0-9C22-186B2A5ED793"
            ]
        },
        "date_time": {
            "type": "string",
            "format": "date-time",
            "examples": [
                "2025-11-13T20:20:39+00:00"
            ]
        },
        "aisp": {
            "type": "object",
            "properties": {
                "legal_name": {
                    "type": "string"
                },
                "brand_name": {
                    "type": "string"
                },
                "domain_name": {
                    "type": "string"
                }
            },
            "required": [
                "legal_name",
                "brand_name",
                "domain_name"
            ]
        },
        "description": {
            "type": "string",
            "maxLength": 140,
            "examples": [
                "Grant access to the account's data."
            ]
        }
    },
    "additionalProperties": false,
    "required": [
        "transaction_id"
    ]
}
"""

    /** `urn:eudi:sca:emandate:1` (file `ts12-urn-eudi-sca-emandate-1-data-model.json`), sha256 7e27182efc4a479d7051884aade820dc6a4f1957728ef87f9e101b1d925a5034. */
    const val EMANDATE: String = """{
    "${'$'}schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "properties": {
        "transaction_id": {
            "type": "string",
            "maxLength": 36,
            "minLength": 1,
            "examples": [
                "8D8AC610-566D-4EF0-9C22-186B2A5ED793"
            ]
        },
        "date_time": {
            "type": "string",
            "format": "date-time",
            "examples": [
                "2025-11-13T20:20:39+00:00"
            ]
        },
        "start_date": {
            "type": "string",
            "format": "date-time",
            "examples": [
                "2025-11-13T20:20:39+00:00"
            ]
        },
        "end_date": {
            "type": "string",
            "format": "date-time",
            "examples": [
                "2025-12-13T20:20:39+00:00"
            ]
        },
        "reference_number": {
            "type": "string",
            "maxLength": 50,
            "minLength": 1,
            "examples": [
                "A-98765"
            ]
        },
        "creditor_id": {
            "type": "string",
            "maxLength": 50,
            "minLength": 1,
            "examples": [
                "FR14ZZZ001122334455"
            ]
        },
        "purpose": {
            "type": "string",
            "maxLength": 1000,
            "examples": [
                "Pay monthly bill"
            ]
        },
        "payment_payload": {
            "${'$'}ref": "ts12-urn-eudi-sca-payment-1-data-model.json"
        }
    },
    "additionalProperties": false,
    "required": [
        "transaction_id"
    ]
}
"""

    /** Built-in type name to its schema. */
    val BY_TYPE: Map<String, String> = mapOf(
        "urn:eudi:sca:payment:1" to PAYMENT,
        "urn:eudi:sca:login_risk_transaction:1" to LOGIN_RISK,
        "urn:eudi:sca:account_access:1" to ACCOUNT_ACCESS,
        "urn:eudi:sca:emandate:1" to EMANDATE,
    )

    /**
     * The file name `urn:eudi:sca:emandate:1` references its payment schema
     * by (`$ref`); resolved to [PAYMENT].
     */
    const val PAYMENT_FILE_NAME: String = "ts12-urn-eudi-sca-payment-1-data-model.json"
}
