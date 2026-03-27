/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use crate::model::{
    DelayBucket, DelayRange, QueryTypeModel, TrafficProfile, TypeWeight, WeightedDomain,
};
use crate::{Error, Result};
use std::borrow::Cow;

const NEGATIVE_DOMAINS: &[WeightedDomain] = &[
    WeightedDomain {
        name: Cow::Borrowed("bootstrap-check.synthetic.invalid"),
        weight: 26,
    },
    WeightedDomain {
        name: Cow::Borrowed("public-api-probe.synthetic.invalid"),
        weight: 24,
    },
    WeightedDomain {
        name: Cow::Borrowed("edge-config-miss.synthetic.invalid"),
        weight: 22,
    },
    WeightedDomain {
        name: Cow::Borrowed("media-bootstrap.synthetic.invalid"),
        weight: 18,
    },
    WeightedDomain {
        name: Cow::Borrowed("fallback-control.synthetic.invalid"),
        weight: 18,
    },
];

const DISALLOWED_DOMAIN_SUBSTRINGS: &[&str] = &[
    "abanca.com",
    "abcchina.com",
    "abnamro.com",
    "acb.com.vn",
    "afirme.com",
    "aib.ie",
    "akbank.com",
    "aktia.fi",
    "aliorbank.pl",
    "alliancebank.com.my",
    "ally.com",
    "alpha.gr",
    "ambankgroup.com",
    "americanexpress.com",
    "anz.co.nz",
    "anz.com",
    "argenta.be",
    "asb.co.nz",
    "asnbank.nl",
    "associatedbank.com",
    "aubank.in",
    "axisbank.com",
    "baccredomatic.com",
    "banamex.com",
    "banbif.com.pe",
    "bancaribe.com.ve",
    "bancobpm.it",
    "bancochile.cl",
    "bancodebogota.com",
    "bancodeoccidente.com.co",
    "bancodobrasil.com.br",
    "bancoestado.cl",
    "bancogeneral.com",
    "bancolombia.com",
    "bancopopular.com.do",
    "bancoppel.com",
    "bandhanbank.com",
    "banesco.com",
    "bangkokbank.com",
    "banistmo.com",
    "bankcomm.com",
    "bankier.pl",
    "bankinter.com",
    "bankislam.com",
    "bankmandiri.co.id",
    "bankofamerica.com",
    "bankofbaroda.in",
    "bankofchina.com",
    "bankofcyprus.com",
    "bankofindia.co.in",
    "bankofireland.com",
    "bankofqueensland.com.au",
    "bankofthewest.com",
    "banorte.com",
    "banquepopulaire.fr",
    "banregio.com",
    "banreservas.com",
    "banrisul.com.br",
    "banrural.com.gt",
    "barclays.com",
    "bb.com.br",
    "bbva.com",
    "bbva.com.ar",
    "bbva.com.co",
    "bbva.mx",
    "bbva.pe",
    "bca.co.id",
    "bci.cl",
    "bci.co.cr",
    "bcp.com.pe",
    "bcr.ro",
    "bcv.ch",
    "bdo.com.ph",
    "belfius.be",
    "bendigoadelaide.com.au",
    "bendigobank.com.au",
    "bforbank.com",
    "bhd.com.do",
    "bidv.com.vn",
    "bmo.com",
    "bni.co.id",
    "bnpparibas.com",
    "bnpparibas.pl",
    "bny.com",
    "bnz.co.nz",
    "boc.cn",
    "bofa.com",
    "bper.it",
    "bpi.com.ph",
    "bradesco.com.br",
    "brd.ro",
    "brex.com",
    "bri.co.id",
    "bsn.com.my",
    "bt.ro",
    "btn.co.id",
    "bunq.com",
    "cadencebank.com",
    "caissedepargne.fr",
    "caixa.gov.br",
    "caixabank.com",
    "cajamar.es",
    "canarabank.com",
    "capitalone.com",
    "cbc.be",
    "ccb.com",
    "cebbank.com",
    "chase.com",
    "chinabank.ph",
    "cib.com.cn",
    "cibc.com",
    "cic.fr",
    "cimb.com",
    "cimbthai.com",
    "citi.com",
    "citicbank.com",
    "citigroup.com",
    "citizensbank.com",
    "cmbc.com.cn",
    "cmbchina.com",
    "comerica.com",
    "commbank.com.au",
    "commerzbank.de",
    "credit-agricole.com",
    "creditmutuel.com",
    "danamon.co.id",
    "danskebank.com",
    "danskebank.fi",
    "davivienda.com",
    "dbs.com",
    "deutsche-bank.de",
    "deutsche-bank.es",
    "discover.com",
    "dkb.de",
    "dnb.no",
    "eastwestbanker.com",
    "erste.hu",
    "eurobank.gr",
    "federalbank.co.in",
    "fidelity.com",
    "fifththird.com",
    "finecobank.com",
    "firstcitizens.com",
    "firstdirect.com",
    "fnb-online.com",
    "galicia.ar",
    "garantibbva.com.tr",
    "garantibbva.ro",
    "ghbank.co.th",
    "globalbank.com.pa",
    "goldmansachs.com",
    "groupebpce.com",
    "grupoaval.com",
    "gs.com",
    "halifax.co.uk",
    "halkbank.com.tr",
    "handelsbanken.com",
    "handelsbanken.fi",
    "hdbank.com.vn",
    "hdfcbank.com",
    "hellenicbank.com",
    "hongleong.com.my",
    "hsbc.com",
    "hsbc.com.mx",
    "hsbc.fr",
    "huntington.com",
    "hxb.com.cn",
    "ibercaja.es",
    "icbc-ltd.com",
    "icbc.com.cn",
    "icicibank.com",
    "idbibank.in",
    "idfcfirstbank.com",
    "illimity.com",
    "inbursa.com",
    "indusind.com",
    "ing.be",
    "ing.com",
    "ing.de",
    "ing.es",
    "ing.pl",
    "inter.co",
    "interbank.pe",
    "intercam.com.mx",
    "intesasanpaolo.com",
    "iob.in",
    "isbank.com.tr",
    "isp.com",
    "itau.cl",
    "itau.com.br",
    "jcb.co.jp",
    "jibunbank.co.jp",
    "jpmorganchase.com",
    "juliusbaer.com",
    "jyskebank.dk",
    "kasikornbank.com",
    "kbc.com",
    "kbcbrussels.be",
    "key.com",
    "kfw.de",
    "kiwibank.co.nz",
    "knab.nl",
    "kotak.com",
    "krungsri.com",
    "krungthai.com",
    "kutxabank.es",
    "labanquepostale.fr",
    "lafise.com",
    "landbank.com",
    "lloydsbank.com",
    "lloydsbankinggroup.com",
    "macquarie.com",
    "macro.com.ar",
    "maybank.co.id",
    "maybank.com",
    "mbank.pl",
    "mbbank.com.vn",
    "mediobanca.com",
    "mercadopago.com",
    "mercantilbanco.com",
    "metrobank.com.ph",
    "metrobankonline.co.uk",
    "migrosbank.ch",
    "millennium.pl",
    "mizuho-fg.co.jp",
    "morganstanley.com",
    "mps.it",
    "mtb.com",
    "mufg.jp",
    "n26.com",
    "nab.com.au",
    "nationwide.co.uk",
    "natwest.com",
    "nbg.gr",
    "nordea.com",
    "nordea.fi",
    "nordjyskebank.dk",
    "ntrs.com",
    "nubank.com.br",
    "ocbc.com",
    "ocbc.id",
    "oldnational.com",
    "op.fi",
    "openbank.es",
    "original.com.br",
    "otpbank.hu",
    "panin.co.id",
    "pbcom.com.ph",
    "pekao.com.pl",
    "permanenttsb.ie",
    "permatabank.com",
    "picpay.com",
    "pingan.com",
    "piraeusbank.gr",
    "pkobp.pl",
    "pnbindia.in",
    "pnc.com",
    "popularenlinea.com",
    "postbank.de",
    "postfinance.ch",
    "promerica.com",
    "provincial.com",
    "psbc.com",
    "publicbankgroup.com",
    "qnb.com.tr",
    "rabobank.com",
    "raiffeisen.ch",
    "raiffeisen.ro",
    "rakuten-bank.co.jp",
    "rbc.com",
    "rblbank.com",
    "rbs.com",
    "rcbc.com",
    "regiobank.nl",
    "regions.com",
    "resonabank.co.jp",
    "rhbgroup.com",
    "royalbank.com",
    "s-pankki.fi",
    "saastopankki.fi",
    "sabadell.com",
    "sacombank.com.vn",
    "santander.cl",
    "santander.co.uk",
    "santander.com",
    "santander.com.ar",
    "santander.com.br",
    "santander.com.mx",
    "santander.pl",
    "sbanken.no",
    "sbi.co.in",
    "scb.co.th",
    "schwab.com",
    "scotiabank.cl",
    "scotiabank.com",
    "scotiabank.com.mx",
    "scotiabank.com.pe",
    "scotiabankcolpatria.com",
    "sebgroup.com",
    "securitybank.com",
    "shinseibank.com",
    "smbc.co.jp",
    "snsbank.nl",
    "societegenerale.com",
    "sofi.com",
    "sonybank.net",
    "southstatebank.com",
    "sparebank1.no",
    "sparkasse.de",
    "spdb.com.cn",
    "standardchartered.com",
    "stgeorge.com.au",
    "storebrand.no",
    "suncorpbank.com.au",
    "supervielle.com.ar",
    "surugabank.co.jp",
    "swedbank.com",
    "sydbank.dk",
    "synchrony.com",
    "td.com",
    "tdbank.com",
    "techcombank.com.vn",
    "tpb.vn",
    "triodos.com",
    "truist.com",
    "tsb.co.uk",
    "ttbbank.com",
    "ubs.com",
    "ucobank.com",
    "ulsterbank.ie",
    "unicaja.com",
    "unicredit.it",
    "unicredit.ro",
    "unicreditgroup.eu",
    "unionbankofindia.co.in",
    "unionbankph.com",
    "uob.co.th",
    "uobgroup.com",
    "usbank.com",
    "vakifbank.com.tr",
    "vanlanschotkempen.com",
    "varo.com",
    "vietcombank.com.vn",
    "vietinbank.vn",
    "virginmoney.com",
    "virginmoneyukplc.com",
    "volkswagenbank.de",
    "vpbank.com.vn",
    "websterbank.com",
    "wellsfargo.com",
    "westpac.co.nz",
    "westpac.com.au",
    "widiba.it",
    "yapikredi.com.tr",
    "yesbank.in",
    "zionsbank.com",
    "ziraatbank.com.tr",
    "zuercherkantonalbank.ch",
];

const CLIENT_SPECIFIC_SUBSTRINGS: &[&str] = &[
    "android.clients.",
    "push-apple",
    "fmfmobile",
    "mask.apple-dns",
    "_dns.resolver.arpa",
    ".local",
    ".lan",
    ".home.arpa",
    "alarmserverlist.",
];

pub(crate) fn builtin_negative_domains() -> Vec<WeightedDomain> {
    NEGATIVE_DOMAINS.to_vec()
}

pub(crate) fn validate_profile(profile: &TrafficProfile) -> Result<()> {
    validate_minimum_positive_domains(profile, 1)?;
    validate_profile_common(profile)
}

fn validate_minimum_positive_domains(profile: &TrafficProfile, minimum: usize) -> Result<()> {
    if profile.positive_domains.len() < minimum {
        return Err(Error::ProfileTooFewPositiveDomains {
            profile: profile.name.clone(),
            minimum,
            found: profile.positive_domains.len(),
        });
    }
    Ok(())
}

fn validate_profile_common(profile: &TrafficProfile) -> Result<()> {
    for domain in profile
        .positive_domains
        .iter()
        .chain(profile.negative_domains.iter())
    {
        if is_disallowed_domain(domain.name.as_ref()) {
            return Err(Error::ProfileDisallowedDomain {
                profile: profile.name.clone(),
                domain: domain.name.to_string(),
            });
        }
    }

    if profile.response_codes.is_empty() {
        return Err(Error::ProfileMissingResponseCodes {
            profile: profile.name.clone(),
        });
    }

    if profile.duplicate_retry_counts.is_empty() {
        return Err(Error::ProfileMissingDuplicateRetryCounts {
            profile: profile.name.clone(),
        });
    }

    match &profile.query_types {
        QueryTypeModel::Explicit(query_types) => {
            validate_query_type_weights(profile, "positive", &query_types.positive)?;
            validate_query_type_weights(profile, "negative", &query_types.negative)?;
            validate_query_type_weights(profile, "reverse", &query_types.reverse)?;
            validate_query_type_weights(profile, "root", &query_types.root)?;
        }
    }

    validate_delay_buckets(
        profile,
        "normal response",
        &profile.normal_response_delay_buckets,
    )?;
    validate_delay_buckets(
        profile,
        "servfail response",
        &profile.servfail_response_delay_buckets,
    )?;
    validate_retry_ranges(
        profile,
        "answered retry",
        &profile.answered_retry_delay_ranges,
    )?;
    validate_retry_ranges(
        profile,
        "unanswered retry",
        &profile.unanswered_retry_delay_ranges,
    )?;

    Ok(())
}

fn validate_query_type_weights(
    profile: &TrafficProfile,
    category: &'static str,
    weights: &[TypeWeight],
) -> Result<()> {
    if weights.is_empty() {
        return Err(Error::ProfileMissingQueryTypeWeights {
            profile: profile.name.clone(),
            category,
        });
    }
    Ok(())
}

fn validate_delay_buckets(
    profile: &TrafficProfile,
    bucket_family: &'static str,
    buckets: &[DelayBucket],
) -> Result<()> {
    if buckets.is_empty() {
        return Err(Error::ProfileMissingResponseDelayBuckets {
            profile: profile.name.clone(),
            bucket_family,
        });
    }

    Ok(())
}

fn validate_retry_ranges(
    profile: &TrafficProfile,
    range_family: &'static str,
    ranges: &[DelayRange],
) -> Result<()> {
    if ranges.is_empty() {
        return Err(Error::ProfileMissingRetryDelayRanges {
            profile: profile.name.clone(),
            range_family,
        });
    }

    Ok(())
}

pub(crate) fn is_root_dns_name(name: &str) -> bool {
    name == "."
}

pub(crate) fn is_reverse_dns_name(name: &str) -> bool {
    if domain_is_ascii_lowercase(name) {
        return is_reverse_dns_name_normalized(name);
    }

    let lower = name.to_ascii_lowercase();
    is_reverse_dns_name_normalized(&lower)
}

fn is_reverse_dns_name_normalized(name: &str) -> bool {
    name.ends_with(".in-addr.arpa") || name.ends_with(".ip6.arpa")
}

pub fn is_disallowed_domain(name: &str) -> bool {
    if domain_is_ascii_lowercase(name) {
        return is_disallowed_domain_normalized(name);
    }

    let lower = name.to_ascii_lowercase();
    is_disallowed_domain_normalized(&lower)
}

fn is_disallowed_domain_normalized(name: &str) -> bool {
    DISALLOWED_DOMAIN_SUBSTRINGS
        .iter()
        .any(|token| domain_contains(token, name))
        || CLIENT_SPECIFIC_SUBSTRINGS
            .iter()
            .any(|token| name.contains(token))
        || name.split('.').any(label_looks_unique)
}

/// Matches `token` against `domain`. Tokens that look like domains (contain `.`)
/// are matched as a domain suffix with a dot boundary, so `key.com` matches
/// `www.key.com` but not `swiftkey.com`. Plain keyword tokens use substring match.
fn domain_contains(token: &str, domain: &str) -> bool {
    if token.contains('.') {
        domain == token
            || domain.ends_with(token)
                && domain.as_bytes().get(domain.len() - token.len() - 1) == Some(&b'.')
    } else {
        domain.contains(token)
    }
}

fn label_looks_unique(label: &str) -> bool {
    if label.len() < 12 {
        return false;
    }

    let digits = label.bytes().filter(u8::is_ascii_digit).count();
    let hex_chars = label.bytes().filter(u8::is_ascii_hexdigit).count();
    digits >= 6 || hex_chars >= 10
}

fn domain_is_ascii_lowercase(name: &str) -> bool {
    !name.bytes().any(|byte| byte.is_ascii_uppercase())
}
