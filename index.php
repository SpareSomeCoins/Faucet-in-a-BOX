<?php

/*
 * Faucet in a BOX
 * https://faucetinabox.com/
 *
 * Copyright 2015 LiveHome Sp. z o. o.
 *
 * All rights reserved. Redistribution and modification of this file in any form is forbidden.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
 *
 */


$version = '62';


if (get_magic_quotes_gpc()) {
    $process = array(&$_GET, &$_POST, &$_COOKIE, &$_REQUEST);
    while (list($key, $val) = each($process)) {
        foreach ($val as $k => $v) {
            unset($process[$key][$k]);
            if (is_array($v)) {
                $process[$key][stripslashes($k)] = $v;
                $process[] = &$process[$key][stripslashes($k)];
            } else {
                $process[$key][stripslashes($k)] = stripslashes($v);
            }
        }
    }
    unset($process);
}

if(stripos($_SERVER['REQUEST_URI'], '@') !== FALSE ||
   stripos(urldecode($_SERVER['REQUEST_URI']), '@') !== FALSE) {
    header("Location: ."); die('Please wait...');
}

session_start();
header('Content-Type: text/html; charset=utf-8');
ini_set('display_errors', false);

$missing_configs = array();

$session_prefix = crc32(__FILE__);

$disable_curl = false;
$verify_peer = true;
$local_cafile = false;
require_once("config.php");
if(!isset($disable_admin_panel)) {
    $disable_admin_panel = false;
    $missing_configs[] = array(
        "name" => "disable_admin_panel",
        "default" => "false",
        "desc" => "Allows to disable Admin Panel for increased security"
    );
}

if(!isset($connection_options)) {
    $connection_options = array(
        'disable_curl' => $disable_curl,
        'local_cafile' => $local_cafile,
        'verify_peer' => $verify_peer,
        'force_ipv4' => false
    );
}
if(!isset($connection_options['verify_peer'])) {
    $connection_options['verify_peer'] = $verify_peer;
}

if (!isset($display_errors)) $display_errors = false;
ini_set('display_errors', $display_errors);
if($display_errors)
    error_reporting(-1);


if(array_key_exists('HTTP_REFERER', $_SERVER)) {
    $referer = $_SERVER['HTTP_REFERER'];
} else {
    $referer = "";
}

$host = parse_url($referer, PHP_URL_HOST);
if($_SERVER['HTTP_HOST'] != $host) {
    if (
        array_key_exists("address_input_name", $_SESSION) &&
        array_key_exists($_SESSION["address_input_name"], $_POST)
    ) {
        $_POST[$_SESSION['address_input_name']] = "";
        if ($display_errors) trigger_error("REFERER CHECK FAILED, ASSUMING CSRF!");
    }
}


require_once('libs/sparesomeAPI.php');

try {
    $sql = new PDO($dbdsn, $dbuser, $dbpass, array(PDO::ATTR_PERSISTENT => true,
                                                   PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION));
} catch(PDOException $e) {
    die("Can't connect to database. Check your config.php.");
}


$template_updates = array(
    array(
        "test" => "/address_input_name/",
        "message" => "Name of the address field has to be updated. Please follow <a href='https://bitcointalk.org/index.php?topic=1094930.msg12231246#msg12231246'>these instructions</a>"
    ),
    array(
        "test" => "/libs\/mmc\.js/",
        "message" => "Add <code>".htmlspecialchars('<script type="text/javascript" src="libs/mmc.js"></script>')."</code> after jQuery in <code>&lt;head&gt;</code> section."
    ),
    array(
        "test" => "/honeypot/",
        "message" => "Add <code><pre>".htmlspecialchars('<input type="text" name="address" class="form-control" style="position: absolute; position: fixed; left: -99999px; top: -99999px; opacity: 0; width: 1px; height: 1px">')."<br>".htmlspecialchars('<input type="checkbox" name="honeypot" style="position: absolute; position: fixed; left: -99999px; top: -99999px; opacity: 0; width: 1px; height: 1px">')."</pre></code> near the input with name <code>".htmlspecialchars('<?php echo $data["address_input_name"]; ?>')."</code>."
    )
);

$db_updates = array(
    15 => array("INSERT IGNORE INTO `Faucetinabox_Settings` (`name`, `value`) VALUES ('version', '15');"),
    17 => array("ALTER TABLE `Faucetinabox_Settings` CHANGE `value` `value` TEXT NOT NULL;", "INSERT IGNORE INTO `Faucetinabox_Settings` (`name`, `value`) VALUES ('balance', 'N/A');"),
    33 => array("INSERT IGNORE INTO `Faucetinabox_Settings` (`name`, `value`) VALUES ('ayah_publisher_key', ''), ('ayah_scoring_key', '');"),
    34 => array("INSERT IGNORE INTO `Faucetinabox_Settings` (`name`, `value`) VALUES ('custom_admin_link_default', 'true')"),
    38 => array("INSERT IGNORE INTO `Faucetinabox_Settings` (`name`, `value`) VALUES ('reverse_proxy', 'none')", "INSERT IGNORE INTO `Faucetinabox_Settings` (`name`, `value`) VALUES ('default_captcha', 'recaptcha')"),
    41 => array("INSERT IGNORE INTO `Faucetinabox_Settings` (`name`, `value`) VALUES ('captchme_public_key', ''), ('captchme_private_key', ''), ('captchme_authentication_key', ''), ('reklamper_enabled', '')"),
    46 => array("INSERT IGNORE INTO `Faucetinabox_Settings` (`name`, `value`) VALUES ('last_balance_check', '0')"),
    54 => array("INSERT IGNORE INTO `Faucetinabox_Settings` (`name`, `value`) VALUES ('funcaptcha_public_key', ''), ('funcaptcha_private_key', '')"),
    55 => array("INSERT IGNORE INTO `Faucetinabox_Settings` (`name`, `value`) VALUES ('block_adblock', ''), ('button_timer', '0')"),
    56 => array("INSERT IGNORE INTO `Faucetinabox_Settings` (`name`, `value`) VALUES ('ip_check_server', ''),('ip_ban_list', ''),('hostname_ban_list', ''),('address_ban_list', '')"),
    58 => ["DELETE FROM `Faucetinabox_Settings` WHERE `name` IN ('captchme_public_key', 'captchme_private_key', 'captchme_authentication_key', 'reklamper_enabled')"],
);

$default_data_query = <<<QUERY
create table if not exists Faucetinabox_Settings (
    `name` varchar(64) not null,
    `value` text not null,
    primary key(`name`)
);
create table if not exists Faucetinabox_IPs (
    `ip` varchar(20) not null,
    `last_used` timestamp not null,
    primary key(`ip`)
);
create table if not exists Faucetinabox_Addresses (
    `address` varchar(60) not null,
    `ref_id` int null,
    `last_used` timestamp not null,
    primary key(`address`)
);
create table if not exists Faucetinabox_Refs (
    `id` int auto_increment not null,
    `address` varchar(60) not null unique,
    `balance` bigint unsigned default 0,
    primary key(`id`)
);
create table if not exists Faucetinabox_Pages (
    `id` int auto_increment not null,
    `url_name` varchar(50) not null unique,
    `name` varchar(255) not null,
    `html` text not null,
    primary key(`id`)
);

INSERT IGNORE INTO Faucetinabox_Settings (name, value) VALUES
('apikey', ''),
('timer', '180'),
('rewards', '90*100, 10*500'),
('referral', '15'),
('solvemedia_challenge_key', ''),
('solvemedia_verification_key', ''),
('solvemedia_auth_key', ''),
('recaptcha_private_key', ''),
('recaptcha_public_key', ''),
('ayah_publisher_key', ''),
('ayah_scoring_key', ''),
('funcaptcha_private_key', ''),
('funcaptcha_public_key', ''),
('name', 'Faucet in a Box'),
('short', 'Just another Faucet in a Box :)'),
('template', 'default'),
('custom_body_cl_default', ''),
('custom_box_bottom_cl_default', ''),
('custom_box_bottom_default', ''),
('custom_box_top_cl_default', ''),
('custom_box_top_default', ''),
('custom_box_left_cl_default', ''),
('custom_box_left_default', ''),
('custom_box_right_cl_default', ''),
('custom_box_right_default', ''),
('custom_css_default', '/* custom_css */\\n/* center everything! */\\n.row {\\n    text-align: center;\\n}\\n#recaptcha_widget_div, #recaptcha_area {\\n    margin: 0 auto;\\n}\\n/* do not center lists */\\nul, ol {\\n    text-align: left;\\n}'),
('custom_footer_cl_default', ''),
('custom_footer_default', ''),
('custom_main_box_cl_default', ''),
('custom_palette_default', ''),
('custom_admin_link_default', 'true'),
('version', '$version'),
('currency', 'BTC'),
('balance', 'N/A'),
('reverse_proxy', 'none'),
('last_balance_check', '0'),
('default_captcha', 'recaptcha'),
('ip_check_server', ''),
('ip_ban_list', ''),
('hostname_ban_list', ''),
('address_ban_list', ''),
('block_adblock', ''),
('button_timer', '0')
;
QUERY;

// ****************** START ADMIN TEMPLATES
$master_template = <<<TEMPLATE
<!DOCTYPE html>
<html>
    <head>
        <title>Faucet in a Box</title>
        <link rel="stylesheet" href="//cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/3.2.0/css/bootstrap.min.css">
        <link rel="stylesheet" id="palette-css" href="data:text/css;base64,IA==">
        <link rel="stylesheet" href="//cdnjs.cloudflare.com/ajax/libs/bootstrap-select/1.6.2/css/bootstrap-select.min.css">
        <script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.1.1/jquery.min.js"></script>
        <script src="//cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/3.2.0/js/bootstrap.min.js"></script>
        <script src="//cdnjs.cloudflare.com/ajax/libs/bootstrap-select/1.6.2/js/bootstrap-select.min.js"></script>
        <style type="text/css">
        a, .btn, tr, td, .glyphicon{
            transition: all 0.2s ease-in;
            -o-transition: all 0.2s ease-in;
            -webkit-transition: all 0.2s ease-in;
            -moz-transition: all 0.2s ease-in;
        }
        .form-group {
            margin: 15px !important;
        }
        textarea.form-control {
            min-height: 120px;
        }
        .tab-content > .active {
            border-radius: 0px 0px 4px 6px;
            margin-top: -1px;
        }
        .prev-box {
            border-radius: 4px;
        }
        .prev-box > .btn {
            min-width: 45px;
            height: 33px;
            font-weight: bold;
        }
        .prev-box > .text-white {
            text-shadow: 0 0 2px black;
        }
        .prev-box > .active {
            margin-top: -2px;
            height: 36px;
            font-weight: bold;
            font-size: 130%;
            border-radius: 3px !important;
            box-shadow: 0px 1px 2px #333;
        }
        .prev-box > .transparent {
            border: 1px dotted #FF0000;
            box-shadow:  inset 0px 0px 5px #FFF;
        }
        .prev-box > .transparent.active {
            box-shadow: 0px 1px 2px #333, inset 0px 0px 5px #FFF;
        }
        .picker-label {
            padding-top: 11px;
        }
        .bg-black{
            background: #000;
        }
        .bg-white{
            background: #fff;
        }
        .text-black{
            color: #000;
        }
        .text-white{
            color: #fff;
        }
        </style>
    </head>
    <body>
        <div class="container">
        <h1>Welcome to your Faucet in a Box Admin Page!</h1><hr>
        <:: content ::>
        </div>
    </body>
</html>
TEMPLATE;

$admin_template = <<<TEMPLATE
<noscript>
    <div class="alert alert-danger text-center" role="alert">
        <p class="lead">
            You have disabled Javascript. Javascript is required for the admin panel to work!
        </p>
    </div>
    <style>
        #admin-content{ display: none !important; }
    </style>
</noscript>

<:: oneclick_update_alert ::>
<:: version_check ::>
<:: changes_saved ::>
<:: new_files ::>
<:: connection_error ::>
<:: curl_warning ::>
<:: send_coins_message ::>
<:: missing_configs ::>
<:: template_updates ::>
<:: nastyhosts_not_allowed ::>

<form method="POST" id="admin-form" class="form-horizontal" role="form">

    <div id="admin-content" role="tabpanel">

        <!-- Nav tabs -->
        <ul class="nav nav-tabs" role="tablist">
            <li role="presentation" class="active"><a href="#basic" aria-controls="basic" role="tab" data-toggle="tab">Basic</a></li>
            <li role="presentation"><a href="#captcha" aria-controls="captcha" role="tab" data-toggle="tab">Captcha</a></li>
            <li role="presentation"><a href="#templates" aria-controls="templates" role="tab" data-toggle="tab">Templates</a></li>
            <li role="presentation"><a href="#pages" aria-controls="pages" role="tab" data-toggle="tab">Pages</a></li>
            <li role="presentation"><a href="#security" aria-controls="security" role="tab" data-toggle="tab">Security</a></li>
            <li role="presentation"><a href="#advanced" aria-controls="advanced" role="tab" data-toggle="tab">Advanced</a></li>
            <li role="presentation"><a href="#referrals" aria-controls="referrals" role="tab" data-toggle="tab">Referrals</a></li>
            <li role="presentation"><a href="#send-coins" aria-controls="send-coins" role="tab" data-toggle="tab">Manually send coins</a></li>
            <li role="presentation"><a href="#reset" aria-controls="reset" role="tab" data-toggle="tab">Factory reset</a></li>
        </ul>

        <div class="tab-content">
            <div role="tabpanel" class="tab-pane active" id="basic">
                <h2>Basic</h2>
                <h3>Faucet Info</h3>
                <div class="form-group">
                    <label for="name" class="control-label">Faucet name</label>
                    <input type="text" class="form-control" name="name" value="<:: name ::>">
                </div>
                <div class="form-group">
                    <label for="short" class="control-label">Short description</label>
                    <input type="text" class="form-control" name="short" value="<:: short ::>">
                </div>

                <h3>Access</h3>
                <div class="row">
                    <div class="col-md-6">
                        <div class="form-group">
                            <:: invalid_key ::>
                            <label for="apikey" class="control-label">SpareSomeCoins.com API key</label>
                            <p>You can get it from <a href="https://sparesomecoins.com/dashboard/" target="_blank">SpareSomeCoins Dashboard</a> (you have to register and log in)</p>
                            <input type="text" class="form-control" name="apikey" value="<:: apikey ::>">
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="form-group">
                            <label for="currency" class="control-label">Currency</label>
                            <p>Select currency associated to your API Key. This setting will not change the currency set in your dashboard, just for use in the script!</p>
                            <select id="currency" class="form-control selectpicker" name="currency" id="currency">
                                <:: currencies ::>
                            </select>
                        </div>
                    </div>
                </div>
                <div class="row">
                    <div class="col-md-6">
                        <div class="form-group">
                            <label for="timer" class="control-label">Timer (in minutes)</label>
                            <p>How often users can get coins from you?</p>
                            <input type="text" class="form-control" name="timer" value="<:: timer ::>">
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="form-group">
                            <label for="referral" class="control-label">Referral earnings:</label>
                            <p>in percents (0 to disable)</p>
                            <input type="text" class="form-control" name="referral" value="<:: referral ::>">
                        </div>
                    </div>
                </div>
                <div class="row">
                    <div class="col-md-6">
                        <div class="form-group">
                            <label for="button-timer" class="control-label">Enable <i>Get reward</i> button after some time</label>
                            <p>Enter number of seconds for which the <i>Get reward</i> button should be disabled</p>
                            <input type="text" class="form-control" name="button_timer" value="<:: button_timer ::>">
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="form-group">
                            <label for="block-adblock" class="control-label"><input type="checkbox" name="block_adblock" <:: block_adblock ::> > Detect and block users with ad blocking software</label>
                            <p><i>Get reward</i> button will be disabled if AdBlock, uBlock or something similar is detected</p>
                        </div>
                    </div>
                </div>
                <h3>Rewards</h3>
                <div class="form-group">
                    <p id="rewards-desc-nojs">How much users can get from you? You can set multiple rewards (separate them with a comma) and set weights for them, to define how plausible each reward will be. <br>Examples: <code>100</code>, <code>50, 150, 300</code>, <code>10*50, 2*100</code>. The last example means 50 satoshi or DOGE 10 out of 12 times, 100 satoshi or DOGE 2 out of 12 times.</p>
                    <p class="hidden" id="rewards-desc-js">
                        How much coins users can get from you? You can set multiple rewards using "Add reward" button. Amount can be either a number (ex. <code>100</code>) or a range (ex. <code>100-500</code>). Chance must be in percentage between 1 and 100. Sum of all chances must be equal 100%.
                    </p>
                    <p>Enter values in satoshi (1 satoshi of xCOIN = 0.00000001 xCOIN) for everything except <strong>INCLUDING</strong> whole currencies like DOGE</p>
                    <input id="rewards-raw" type="text" class="form-control" name="rewards" value="<:: rewards ::>">
                    <div id="rewards-box" class="hidden">
                        <div class="alert alert-info">
                            <b>PREVIEW:</b> Possible rewards: <span id="rewards-preview">loading...</span>
                        </div>
                        <table class="table">
                            <thead>
                                <tr>
                                    <th>Amount</th>
                                    <th>Chance (in %)</th>
                                    <th class="text-center">Options</th>
                                </tr>
                            </thead>
                            <tbody>
                            </tbody>
                        </table>
                        <div class="alert alert-warning hidden rewards-warning">
                            Some incorrect fields were discarded. Amount can be either a number (eg. "100") or a range (eg. "100-200"). If amount is a range, the second number must be greater than the first one (eg. "200-100" is incorrect). Chance must be greater than 0 and lower than 100.
                        </div>
                        <div class="alert alert-danger hidden rewards-alert">
                            Sum of rewards' chances is not equal to 100 (%).
                            (<i class="math"></i>)
                            <a href="#" id="rewards-auto-fix" class="pull-right">Auto fix (this will remove all invalid rows)</a>
                        </div>
                        <button id="add-reward" class="btn btn-primary">Add reward</button>
                    </div>
                </div>
            </div>
            <div role="tabpanel" class="tab-pane" id="captcha">
                <h2>Captcha</h2>
                <div class="row">
                    <div class="form-group">
                        <p class="alert alert-info">Some captcha systems may be unsafe and fail to stop bots. FunCaptcha is considered the safest, but you should always read opinions about your chosen Captcha system first.</p>
                        <label for="default_captcha" class="control-label">Default captcha:</label>
                        <select class="form-control selectpicker" name="default_captcha" id="default_captcha">
                            <option value="SolveMedia">SolveMedia</option>
                            <option value="reCaptcha">reCaptcha</option>
                            <option value="AreYouAHuman">Are You A Human</option>
                            <option value="FunCaptcha">FunCaptcha</option>
                        </select>
                    </div>
                </div>
                <div class="row">
                    <div class="col-lg-6 col-md-6">
                        <div class="well">
                            <h4>reCaptcha</h4>
                            <div class="form-group" id="recaptcha">
                                <p>Get your keys <a href="https://www.google.com/recaptcha/admin#list">here</a>.</p>
                                <label for="recaptcha_public_key" class="control-label">reCaptcha public key:</label>
                                <input type="text" class="form-control" name="recaptcha_public_key" value="<:: recaptcha_public_key ::>">
                                <label for="recaptcha_private_key" class="control-label">reCaptcha private key:</label>
                                <input type="text" class="form-control" name="recaptcha_private_key" value="<:: recaptcha_private_key ::>">
                                <label><input type="checkbox" class="captcha-disable-checkbox"> Turn on this captcha system</label>
                            </div>
                        </div>
                    </div>
                    <div class="col-lg-6 col-md-6">
                        <div class="well">
                            <h4>Are You A Human</h4>
                            <div class="form-group" id="ayah">
                                <p>Get your keys <a href="https://portal.areyouahuman.com/dashboard">here</a>.</p>
                                <label for="ayah_publisher_key" class="control-label">Are You A Human publisher key:</label>
                                <input type="text" class="form-control" name="ayah_publisher_key" value="<:: ayah_publisher_key ::>">
                                <label for="ayah_scoring_key" class="control-label">Are You A Human scoring key:</label>
                                <input type="text" class="form-control" name="ayah_scoring_key" value="<:: ayah_scoring_key ::>">
                                <label><input type="checkbox" class="captcha-disable-checkbox"> Turn on this captcha system</label>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="row">
                    <div class="col-lg-6 col-md-6">
                        <div class="well">
                            <h4>SolveMedia</h4>
                            <div class="form-group" id="solvemedia">
                                <p>Get your keys <a href="https://portal.solvemedia.com/portal/">here</a> (select <em>Sites</em> from the menu after logging in).</p>
                                <label for="solvemedia_challenge_key" class="control-label">SolveMedia challenge key:</label>
                                <input type="text" class="form-control" name="solvemedia_challenge_key" value="<:: solvemedia_challenge_key ::>">
                                <label for="solvemedia_verification_key" class="control-label">SolveMedia verification key:</label>
                                <input type="text" class="form-control" name="solvemedia_verification_key" value="<:: solvemedia_verification_key ::>">
                                <label for="solvemedia_auth_key" class="control-label">SolveMedia authentication key:</label>
                                <input type="text" class="form-control" name="solvemedia_auth_key" value="<:: solvemedia_auth_key ::>">
                                <label><input type="checkbox" class="captcha-disable-checkbox"> Turn on this captcha system</label>
                            </div>
                        </div>
                    </div>
                    <div class="col-lg-6 col-md-6">
                        <div class="well">
                            <h4>FunCaptcha</h4>
                            <div class="form-group" id="funcaptcha">
                                <p>Get your keys <a href="https://www.funcaptcha.com/domain-settings">here</a>.</p>
                                <label for="funcaptcha_public_key" class="control-label">FunCaptcha public key:</label>
                                <input type="text" class="form-control" name="funcaptcha_public_key" value="<:: funcaptcha_public_key ::>">
                                <label for="funcaptcha_private_key" class="control-label">FunCaptcha private key:</label>
                                <input type="text" class="form-control" name="funcaptcha_private_key" value="<:: funcaptcha_private_key ::>">
                                <label><input type="checkbox" class="captcha-disable-checkbox"> Turn on this captcha system</label>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div role="tabpanel" class="tab-pane" id="templates">
                <h2>Template options</h2>
                <div class="form-group">
                    <div class="col-xs-12 col-sm-2 col-lg-1">
                        <label for="template" class="control-label">Template:</label>
                    </div>
                    <div class="col-xs-3">
                        <select id="template-select" name="template" class="selectpicker"><:: templates ::></select>
                    </div>
                </div>
                <div id="template-options">
                <:: template_options ::>
                </div>
            </div>
            <div role="tabpanel" class="tab-pane" id="pages">
                <h2>Pages</h2>
                <p>Here you can create, delete and edit custom static pages.</p>
                <ul class="nav nav-tabs pages-nav" role="tablist">
                    <li class="pull-right"><button type="button" id="pageAddButton" class="btn btn-info"><span class="glyphicon">+</span> Add new page</button></li>
                    <:: pages_nav ::>
                </ul>
                <div id="pages-inner" class="tab-content">
                    <:: pages ::>
                </div>
            </div>
            <div role="tabpanel" class="tab-pane" id="security">
                <h2>Security</h2>
                <h3>Bot protection</h3>
                <div class="form-group">
                    <label for="ip_check_server" class="control-label">Use external IP address check service (it'll also report suspicious addresses to this service):</label>
                    <select id="ip_check_server" name="ip_check_server" class="form-control selectpicker">
                        <option value="http://v1.nastyhosts.com/">NastyHosts.com</option>
                        <option value="">Disabled</option>
                    </select>
                </div>
                <div class="form-group">
                    <label for="ip_ban_list" class="control-label">List of IP addresses or IP networks in CIDR notation to ban (one value per line)</label>
                    <textarea class="form-control" name="ip_ban_list" id="ip_ban_list" placeholder="Example value:
127.0.0.0/8
172.16.0.1
192.168.0.0/24"><:: ip_ban_list ::></textarea>
                </div>
                <div class="form-group">
                    <label for="hostname_ban_list" class="control-label">List of hostnames to ban. Partial match is enough. Requires external IP address check service enabled. (one value per line)</label>
                    <textarea class="form-control" name="hostname_ban_list" id="hostname_ban_list" placeholder="Example value:
proxy
compute.amazonaws.com"><:: hostname_ban_list ::></textarea>
                </div>
                <div class="form-group">
                    <label for="address_ban_list" class="control-label">List of cryptocurrency addresses to ban (one address per line)</label>
                    <textarea class="form-control" name="address_ban_list" id="address_ban_list" placeholder="Example value:
1HmUrGAf4Bz9KMX6Pg67RA2VZgWVPnpyvS
13q29zfcesTiZoed1BNFr3VYr4zBGfuwW4"><:: address_ban_list ::></textarea>
                </div>
            </div>
            <div role="tabpanel" class="tab-pane" id="advanced">
                <h2>Advanced</h2>
                <h3>Reverse Proxy</h3>
                <div class="form-group">
                    <p class="alert alert-danger"><b>Be careful! This is an advanced feature. Don't use it unless you know what you're doing. If you set it wrong or you don't properly configure your proxy AND your server YOU MAY LOSE YOUR COINS!</b></p>
                    <p class="alert alert-info">This feature is experimental! It may not work properly and may lead you to losing coins. You have been warned.</p>
                    <p>This setting allows you to change the method of identifying users. By default Faucet in a Box will use the connecting IP address. Hovewer if you're using a reverse proxy, like CloudFlare or Incapsula, the connecting IP address will always be the address of the proxy. That results in all faucet users sharing the same timer. If you set this option to a correct proxy, then Faucet in a Box will use a corresponding HTTP Header instead of IP address.</p>
                    <p>However you MUST prevent anyone from bypassing the proxy. HTTP Headers can be spoofed, so if someone can access your page directly, then he can send his own headers, effectively ignoring the timer you've set and stealing all your coins!</p>
                    <p>Faucet in a Box has a security feature that will disable Reverse Proxy support if it detects any connection that has bypassed the proxy. Hovewer the detection is not perfect, so you shouldn't rely on it. Instead make proper precautions, for example by configuring your firewall to only allow connections from your proxy IP addresses.</p>
                    <p>If you're using a Reverse Proxy (CloudFlare or Incapsula) choose it from the list below. If your provider is not listed below contact us at support@sparesomecoins.com</p>
                    <p><em>None</em> is always a safe setting, but - as explained above - the timer may be shared between all your users if you're using a proxy.</p>
                    <:: reverse_proxy_changed_alert ::>
                    <label for="reverse_proxy" class="control-label">Reverse Proxy provider:</label>
                    <select id="reverse_proxy" name="reverse_proxy" class="form-control selectpicker">
                        <option value="cloudflare">CloudFlare (CF-Connecting-IP)</option>
                        <option value="incapsula">Incapsula (Incap-Client-IP)</option>
                        <option value="none">None (Connecting IP address)</option>
                    </select>
                </div>
            </div>
            <div role="tabpanel" class="tab-pane" id="referrals">
                <h2>Referrals</h2>
                <div class="alert alert-info">
                    On this tab you can check all addresses which have referral.
                </div>
                <div class="row" style="padding: 15px 0 30px;">
                    <div class="col-md-10">
                        <input type="text" class="form-control" id="referral_address" value="" placeholder="Referral address">
                    </div>
                    <div class="col-md-2">
                        <button class="btn btn-primary" id="check_referral" style="width: 100%;">Check</button>
                    </div>
                </div>
                <div class="alert alert-danger hidden" id="referral-ajax-error">
                    An error occurred while receiving addresses with this referral. Please try again later or contact <a href="http://support.sparesomecoins.com/" target="_blank">support team</a>.
                </div>
                <table class="table hidden" id="referral_list">
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>Address</th>
                            <th>Referral</th>
                        </tr>
                    </thead>
                    <tbody>

                    </tbody>
                </table>

                <div style="height: 30px;"></div>

            </div>
            <div role="tabpanel" class="tab-pane" id="send-coins">
                <h2>Manually send coins</h2>
                <div class="form-group">
                    <p class="alert alert-info">You can use the form below to send coins to given address manaully</p>
                    <label for="" class="control-label">Amount in satoshi:</label>
                    <input type="text" class="form-control" name="send_coins_amount" value="1" id="input_send_coins_amount">
                    <label for="" class="control-label">Currency:</label>
                    <input type="text" class="form-control" name="send_coins_currency" value="<:: currency ::>" disabled>
                    <label for="" class="control-label">Receiver address:</label>
                    <input type="text" class="form-control" name="send_coins_address" value=""id="input_send_coins_address">
                </div>
                <div class="form-group">
                    <div class="alert alert-info">
                        Are you sure you would like to send <span id="send_coins_satoshi">0</span> satoshi (<span id="send_coins_bitcoins">0.00000000</span> <:: currency ::>) to <span id="send_coins_address">address</span>?
                        <input class="btn btn-primary pull-right" style="margin-top: -7px;" type="submit" name="send_coins" value="Yes, send coins">
                    </div>
                </div>
            </div>
            <div role="tabpanel" class="tab-pane" id="reset">
                <h2>Factory reset</h2>
                <div class="alert alert-danger">
                    This will reset all settings except: API key, captcha keys, admin password and pages. Deleted data can't be recovered!<br>
                    Please select the checkbox to confirm and click button below.
                </div>
                <div class="text-center">
                    <label>
                        <input type="checkbox" name="factory_reset_confirm">
                        Yes, I want to reset back to factory settings
                    </label>
                </div>
                <div class="text-center">
                    <input type="submit" name="reset" class="btn btn-warning btn-lg" style="" value="Reset settings to defaults">
                </div>
            </div>
        </div>

    </div>

    <hr>

    <div class="form-group">
        <button type="submit" name="save_settings" class="btn btn-success btn-lg">
            <span class="glyphicon glyphicon-ok"></span>
            Save changes
        </button>
        <a href="?p=logout" class="btn btn-default btn-lg pull-right">
            <span class="glyphicon glyphicon-log-out"></span>
            Logout
        </a>
    </div>
    <script type="text/javascript">

    if (typeof btoa == "undefined") {
          //  discuss at: http://phpjs.org/functions/base64_encode/
          // original by: Tyler Akins (http://rumkin.com)
          // improved by: Bayron Guevara
          // improved by: Thunder.m
          // improved by: Kevin van Zonneveld (http://kevin.vanzonneveld.net)
          // improved by: Kevin van Zonneveld (http://kevin.vanzonneveld.net)
          // improved by: Rafał Kukawski (http://kukawski.pl)
          // bugfixed by: Pellentesque Malesuada
        function btoa(e){var t,r,c,a,n,h,o,A,i="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",d=0,l=0,u="",C=[];if(!e)return e;e=unescape(encodeURIComponent(e));do t=e.charCodeAt(d++),r=e.charCodeAt(d++),c=e.charCodeAt(d++),A=t<<16|r<<8|c,a=A>>18&63,n=A>>12&63,h=A>>6&63,o=63&A,C[l++]=i.charAt(a)+i.charAt(n)+i.charAt(h)+i.charAt(o);while(d<e.length);u=C.join("");var s=e.length%3;return(s?u.slice(0,s-3):u)+"===".slice(s||3)}
    }


    function renumberPages(){
        $(".pages-nav > li").each(function(index){
            if(index != 0){
                $(this).children().first().attr("href", "#page-wrap-" + index);
                $(this).children().first().text("Page " + index);
            }
        });
        $("#pages-inner > div.tab-pane").each(function(index){
            var i = index+1;
            $(this).attr("id", "page-wrap-" + i);
            $(this).children().each(function(i2){
                var ending = "html";
                var item = "textarea";
                if(i2 == 0){
                    ending = "name";
                    item = "input";
                }

                $(this).children('label').attr("for", "pages." + i + "." + ending);
                $(this).children(item).attr("id", "pages." + i + "." + ending).attr("name", "pages[" + i + "][" + ending + "]");
            });
        });
    }

    function deletePage(btn) {
        $(btn).parent().remove();
        $(".pages-nav > .active").remove();
        $(".pages-nav > li:nth-child(2) > a").tab('show');
        renumberPages();
    }

    function reloadSendCoinsConfirmation() {

        var satoshi = $("#input_send_coins_amount").val();
        var bitcoin = satoshi / 100000000;
        var address = $("#input_send_coins_address").val();

        $("#send_coins_satoshi").text(satoshi);
        $("#send_coins_bitcoins").text(bitcoin.toFixed(8));
        $("#send_coins_address").text(address);

    }

    var tmp = [];

    $(function() {

        $("#check_referral").click(function (e) {

            $(this).attr("disabled", true).text("Checking...");

            $.ajax(document.location.href, {method: "POST", data: {action: "check_referrals", referral: $("#referral_address").val()}})
            .done(function (data) {

                $("#check_referral").attr("disabled", false).text("Check");

                if (data.status == 200) {

                    $("#referral-ajax-error").addClass("hidden");

                    $("#referral_list").removeClass("hidden").find("tbody").html("");

                    for (i in data.addresses) {
                        var el = data.addresses[i];

                        $("#referral_list tbody").append(
                            $("<tr>").append(
                                $("<td>").html( (i+1) + "." )
                            ).append(
                                $("<td>").text(el.address).append(
                                    $("<span>").addClass("glyphicon glyphicon-chevron-right pull-right")
                                )
                            ).append(
                                $("<td>").text(el.referral)
                            )
                        );

                    }

                    if (data.addresses.length == 0) {
                        $("#referral_list tbody").append(
                            $("<tr>").append(
                                $("<td>").attr("colspan", 5).append(
                                    $("<p>").addClass("lead text-center text-muted").text("No addresses found")
                                )
                            )
                        );
                    }

                } else {
                    $("#referral-ajax-error").removeClass("hidden");
                    $("#referral_list").addClass("hidden");
                }

            }).fail(function () {
                $("#referral-ajax-error").removeClass("hidden");
                $("#referral_list").addClass("hidden");
            });

        });

        $("#admin-form").submit(function (e) {
            e.preventDefault();
        });

        $("#admin-form input[type=submit], #admin-form button[type=submit]").click(function (e) {
            e.preventDefault();
            var data = btoa($("#admin-form").serialize());
            $("<form>").attr("method", "POST").append(
                $("<input>")
                    .attr("type", "hidden")
                    .attr("name", "encoded_data")
                    .val(data)
            ).append(
                $("<input>")
                    .attr("type", "hidden")
                    .attr("name", $(this).attr("name"))
                    .val( $(this).val().length > 0 ? $(this).val() : $(this).text() )
            ).hide().appendTo('body').submit();
        });

        $("#input_send_coins_amount, #input_send_coins_address").change(reloadSendCoinsConfirmation).keydown(reloadSendCoinsConfirmation).keyup(reloadSendCoinsConfirmation).keypress(reloadSendCoinsConfirmation);

        $("#pageAddButton").click(function() {
            var i = $("#pages-inner").children("div").length.toString();
            var j = parseInt(i)+1;
            var newpage = <:: page_form_template ::>
                        .replace(/<:: i ::>/g, i)
                        .replace("<:: html ::>", '')
                        .replace("<:: page_name ::>", '');
            $("#pages-inner").append(newpage);
            var newtab = <:: page_nav_template ::>
                        .replace(/<:: i ::>/g, i);
            $('.pages-nav').append(newtab);
            renumberPages();
            $(".pages-nav > li").last().children().first().tab('show');
        });
        $(".pages-nav > li:nth-child(2)").addClass('active');
        $('#pages-inner').children().first().addClass('active');

        $('.pages-nav a').click(function (e) {
            e.preventDefault();
            $(this).tab('show');
        });
        $("#template-select").change(function() {
            var t = $(this).val();
            $.post("", { "get_options": t }, function(data) { $("#template-options").html(data); $('.selectpicker').selectpicker(); });
        });
        $("#reverse_proxy").val("<:: reverse_proxy ::>"); //must be before selectpicker render
        $("#default_captcha").val("<:: default_captcha ::>"); //must be before selectpicker render
        $("#ip_check_server").val("<:: ip_check_server ::>"); //must be before selectpicker render
        $('.selectpicker').selectpicker(); //render selectpicker on page load

        $('.nav-tabs a').click(function (e) {
            e.preventDefault()
            $(this).tab('show');
            if (typeof localStorage !== "undefined") {
                localStorage["current_tab"] = $(this).attr('href');
            }
        });

        if (typeof localStorage !== "undefined" && typeof localStorage["current_tab"] !== "undefined") {
            $('a[href=' + localStorage["current_tab"] + ']').tab('show');
        }

        $(".captcha-disable-checkbox").each(function(){
            $(this).parent().parent().find("input[type=text]").each(function(){
                if ($(this).val() == '') {
                    $(this).parent().find(".captcha-disable-checkbox").attr("checked", false);
                    $(this).parent().find("input[type=text]").attr("readonly", true);
                } else {
                    $(this).parent().find(".captcha-disable-checkbox").attr("checked", true);
                    $(this).parent().find("input[type=text]").attr("readonly", false);
                }
            });
        }).change(function(){
            if ($(this).prop("checked")) {
                $(this).parent().parent().find("input[type=text]").each(function(){
                    $(this).val(tmp[$(this).attr("name")]);
                    $(this).attr("readonly", false);
                });
            } else {
                $(this).parent().parent().find("input[type=text]").each(function(){
                    tmp[$(this).attr("name")] = $(this).val();
                    $(this).val("");
                    $(this).attr("readonly", true);
                });
            }
        });

        RewardsSystem.init();
    });



var RewardsSystem = {

    init: function() {

        $('#rewards-raw').addClass('hidden');
        $('#rewards-box').removeClass('hidden');

        $('#rewards-desc-nojs').addClass('hidden');
        $('#rewards-desc-js').removeClass('hidden');

        $('#add-reward').click(function (e) {
            e.preventDefault();
            RewardsSystem.addRow();
        });

        $('#rewards-auto-fix').click(function (e) {
            e.preventDefault();
            RewardsSystem.autoFix();
            RewardsSystem.autoFix();
        });

        $('#currency').change(RewardsSystem.rewardsUpdate);

        RewardsSystem.fromRawData();

    },

    fromRawData: function() {
        var rewards = [];

        var raw = $('#rewards-raw').val().trim().split(' ');
        for (i in raw) {
            var reward = raw[i];
            if (reward.trim() == '') continue;
            reward = reward.split('*');
            if (typeof reward[1] == 'undefined') {
                rewards[rewards.length] = {
                    amount: RewardsSystem.parseAmount(reward[0]),
                    chance: 1
                };
            } else {
                rewards[rewards.length] = {
                    amount: RewardsSystem.parseAmount(reward[1]),
                    chance: parseFloat(parseFloat(reward[0]).toFixed(2))
                };
            }
        }

        var chance_sum = 0;

        for (i in rewards) {
            chance_sum += rewards[i].chance;
        }

        rewards.sort(function (a,b) {
            return b.chance - a.chance;
        });

        RewardsSystem.updateCurrentRewrads(rewards, chance_sum);
        RewardsSystem.rewardsUpdate();
    },

    addRow: function () {
        var tr = $('<tr>')
            .append(
                $('<td>').addClass('form-group').append(
                    $('<input>').addClass('form-control reward-amount').attr({
                        type: 'text'
                    })
                )
            )
            .append(
                $('<td>').addClass('form-group').append(
                    $('<input>').addClass('form-control reward-chance').attr({
                        type: 'number',
                        min: '1',
                        step: '0.01'
                    })
                )
            )
            .append(
                $('<td>').addClass('text-center').append(
                    $('<span>').addClass('btn btn-warning').text('Delete')
                )
            );
        tr.find('span').click(RewardsSystem.delete);
        tr.find('input').on('change click blur keypress keydown keyup', RewardsSystem.rewardsUpdate);

        $('#rewards-box table tbody').append(tr);
    },

    getCurrentRewards: function () {
        var rewards = [];
        var sum_chance = 0;
        $('#rewards-box table tbody tr').each(function (i, t) {
            var amount = $(t).find('.reward-amount').val().trim();
            var chance = parseFloat($(t).find('.reward-chance').val().trim());
            if (isNaN(chance)) chance = 0;
            if (RewardsSystem.validateAmount(amount) && !isNaN(chance) && chance > 0) {
                chance = parseFloat(chance.toFixed(2));
                sum_chance += chance;
                rewards[rewards.length] = {
                    amount: amount,
                    chance: chance
                };
            }
        });
        return {
            'rewards': rewards,
            'sum': sum_chance
        };
    },

    updateCurrentRewrads: function (rewards, sum) {
        if (typeof sum == 'undefined') sum = 100;
        $('#rewards-box table tbody').html('');
        for (i in rewards) {
            var reward = rewards[i];
            RewardsSystem.addRow();
            $('#rewards-box table tr').last().find('.reward-amount').val(reward.amount);
            $('#rewards-box table tr').last().find('.reward-chance').val(parseFloat((reward.chance / sum * 100.0).toFixed(2)));
        }
    },

    delete: function () {
        $(this).parent().parent().remove();
        RewardsSystem.rewardsUpdate();
    },

    autoFix: function() {
        var rewards = RewardsSystem.getCurrentRewards();
        var diff = rewards.sum / 100;

        rewards.sum = 0;
        rewards.count = 0;
        rewards.omit = 0;
        for (i in rewards.rewards) {
            if (rewards.rewards[i].chance / diff >= 1) {
                rewards.sum += rewards.rewards[i].chance;
                rewards.count++;
            } else {
                rewards.omit += rewards.rewards[i].chance;
            }
        }

        var diff = rewards.sum / (100-rewards.omit);

        for (i in rewards.rewards) {
            if (rewards.rewards[i].chance / diff >= 1) {
                rewards.rewards[i].chance = rewards.rewards[i].chance / diff;
            }
        }

        RewardsSystem.updateCurrentRewrads(rewards.rewards);
        RewardsSystem.rewardsUpdate();
    },

    parseAmount: function (amount) {

        var new_amount = '';

        for (i = 0; i < amount.length; i++) {

            var char = amount[i];

            if (char == ',') char = '.';

            if (char == '.' && i == 0) {
                new_amount += '0.';
            } else if (!isNaN(parseInt(char)) || ((char == '-' || char == '.') && i > 0 && i < amount.length-1)) {
                new_amount += char;
            }

        }

        return new_amount;

    },

    validateAmount: function(amount) {
        if (amount.indexOf('-') != -1) {
            var from = parseFloat(amount.substring(0, amount.indexOf('-')));
            var to = parseFloat(amount.substring(amount.indexOf('-')+1));
            return (!isNaN(from) && !isNaN(to) && to > from && from > 0);
        } else {
            var num = parseFloat(amount);
            return (!isNaN(num) && num > 0);
        }
    },

    rewardsUpdate: function (e) {

        if (typeof e == 'undefined' || typeof e.type == 'undefined') {
            e = {
                type: ''
            };
        }

        var raw = '';
        var preview = '';

        var new_chance_sum = 0.0;
        var chance_math = '';


        $('.rewards-warning').addClass('hidden');

        $('#rewards-box table tbody tr').each(function (i, t) {


            var amount = RewardsSystem.parseAmount($(t).find('.reward-amount').val().trim());
            var chance = parseFloat($(t).find('.reward-chance').val().trim());

            if (isNaN(chance)) chance = 0;

            $(t).find('.reward-amount').parent().removeClass('has-warning');
            $(t).find('.reward-chance').parent().removeClass('has-warning');

            var validAmount = RewardsSystem.validateAmount(amount);
            var validChance = (!isNaN(chance) && chance > 0);

            if (validAmount && validChance) {

                chance = parseFloat(chance.toFixed(2));

                if ($(t).find('.reward-amount').val() != amount && e.type == 'blur') {
                    $(t).find('.reward-amount').val(amount);
                }
                if ($(t).find('.reward-chance').val() != chance) {
                    $(t).find('.reward-chance').val(chance);
                }

                new_chance_sum += chance;
                chance_math += (i > 0 ? ' + ' : '') + chance + '%';

                raw += (i > 0 ? ', ' : '') + chance + '*' + amount;
                preview += (i > 0 ? ', ' : '') + amount + ' (' + chance + '%)';

            } else if ((!validAmount && validChance) || (validAmount && !validChance)) {
                $('.rewards-warning').removeClass('hidden');
                if (!validAmount) {
                    $(t).find('.reward-amount').parent().addClass('has-warning');
                }
                if (!validChance) {
                    $(t).find('.reward-chance').parent().addClass('has-warning');
                }
            }

        });

        $('#rewards-raw').val(raw);
        $('#rewards-preview').text(preview + ' ' + ($('#currency').val() == 'DOGE' ? 'DOGE' : 'satoshi'));

        if (parseFloat(new_chance_sum.toFixed(2)) != '100') {
            $('.rewards-alert').removeClass('hidden');
            $('.rewards-alert .math').text(chance_math + ' = ' + new_chance_sum.toFixed(2) + '%');
        } else {
            $('.rewards-alert').addClass('hidden');
        }

    },

};


    </script>
</form>
TEMPLATE;

$admin_login_template = <<<TEMPLATE
<form method="POST" class="form-horizontal" role="form">
    <div class="form-group">
        <label for="password" class="control-label">Password:</label>
        <input type="password" class="form-control" name="password">
    </div>
    <div class="form-group">
        <input type="submit" class="btn btn-primary btn-lg" value="Login">
    </div>
</form>
<div class="alert alert-warning alert-dismissible" role="alert">
  <button type="button" class="close" data-dismiss="alert"><span aria-hidden="true">&times;</span><span class="sr-only">Close</span></button>
Don't remember? <a href="?p=password-reset">Reset your password</a>.
</div>
TEMPLATE;

$session_error_template = <<<TEMPLATE
<div class="alert alert-danger" role="alert">
    There was a problem with accessing your session data on the server. Check your server logs and contact your hosting provider for further help.
</div>
TEMPLATE;

$login_error_template = <<<TEMPLATE
<div class="alert alert-danger" role="alert">
    <span class="glyphicon glyphicon-remove"></span>
    Incorrect password.
</div>
TEMPLATE;

$pass_template = <<<TEMPLATE
<div class="alert alert-info" role="alert">
    Your password: <:: password ::>. Make sure to save it. <a class="alert-link" href="?p=admin">Click here to continue</a>.
</div>
TEMPLATE;

$pass_reset_template = <<<TEMPLATE
<form method="POST">
    <div class="form-group">
        <label for="dbpass" class="control-label">To reset your Admin Password, enter your database password here:</label>
        <input type="password" class="form-control" name="dbpass">
    </div>
    <p class="form-group alert alert-info" role="alert">
        You must enter the same password you've entered in your config.php file.
    </p>
    <input type="submit" class="form-group pull-right btn btn-warning" value="Reset password">
</form>
TEMPLATE;

$invalid_key_error_template = <<<TEMPLATE
<div class="alert alert-danger" role="alert">
    You've entered an invalid API key!
</div>
TEMPLATE;

$oneclick_update_button_template = <<<TEMPLATE
or
<input type="hidden" name="task" value="oneclick-update">
<input type="submit" class="btn btn-primary" value="Update automatically">
TEMPLATE;

$new_version_template = <<<TEMPLATE
<form method="POST">
    <div class="alert alert-info alert-dismissible" role="alert">
        <button type="button" class="close" data-dismiss="alert">
            <span aria-hidden="true">&times;</span>
            <span class="sr-only">Close</span>
        </button>
        <span style="line-height: 34px">
            There's a new version of Faucet in a Box available!
            Your version: $version; new version: <b><:: version ::></b>
        </span>
        <span class="pull-right text-right">
            <a class="btn btn-primary" href="<:: url ::>" target="_blank">Download version <:: version ::></a>
            <:: oneclick_update_button ::>
            <br><br>
            <a href="https://faucetinabox.com/#update" target="_blank">
                Manual update instructions
            </a>
        </span>
        <:: changelog ::>
    </div>
</form>
TEMPLATE;

$page_nav_template = <<<TEMPLATE
    <li><a href="#page-wrap-<:: i ::>" role="tab" data-toggle="tab">Page <:: i ::></a></li>
TEMPLATE;

$page_form_template = <<<TEMPLATE
<div class="page-wrap panel panel-default tab-pane" id="page-wrap-<:: i ::>">
    <div class="form-group">
        <label class="control-label" for="pages.<:: i ::>.name">Page name:</label>
        <input class="form-control" type="text" id="pages.<:: i ::>.name" name="pages[<:: i ::>][name]" value="<:: page_name ::>">
    </div>
    <div class="form-group">
        <label class="control-label" for="pages.<:: i ::>.html">HTML content:</label>
        <textarea class="form-control" id="pages.<:: i ::>.html" name="pages[<:: i ::>][html]"><:: html ::></textarea>
    </div>
    <button type="button" class="btn btn-sm pageDeleteButton" onclick="deletePage(this);">Delete this page</button>
</div>
TEMPLATE;

$changes_saved_template = <<<TEMPLATE
<p class="alert alert-success">
    <span class="glyphicon glyphicon-ok"></span>
    Changes successfully saved!
</p>
TEMPLATE;

$oneclick_update_success_template = <<<TEMPLATE
<p class="alert alert-success">
    <span class="glyphicon glyphicon-ok"></span>
    Faucet in a BOX script was successfully updated to the newest version!
</p>
TEMPLATE;

$nastyhosts_not_allowed_template = <<<TEMPLATE
<p class="alert alert-danger">
    <span class="glyphicon glyphicon-remove"></span>
    You can't enable NastyHosts.com, because your IP address is marked as suspicious and you won't be able to access Admin Panel.
</p>
TEMPLATE;

$oneclick_update_fail_template = <<<TEMPLATE
<p class="alert alert-danger">
    <span class="glyphicon glyphicon-remove"></span>
    An error occurred while updating Faucet in a BOX script. Please install new version manually.
</p>
TEMPLATE;

$new_files_template = <<<TEMPLATE
<div class="alert alert-danger">
    Some of your template files need to be updated manually. Please compare original and new files and merge the changes:
    <ul>
        <:: new_files ::>
    </ul>
    Remember to remove <code>.new</code> files when you're done.
</div>
TEMPLATE;

$connection_error_template = <<<TEMPLATE
<p class="alert alert-danger">Error connecting to <a href="https://sparesomecoins.com">SpareSomeCoins.com API</a>. Either your hosting provider doesn't support external connections or SpareSomeCoins.com API is down. Send an email to <a href="mailto:support@faucetbox.com">support@faucetbox.com</a> if you need help.</p>
TEMPLATE;

$reverse_proxy_changed_alert_template = <<<TEMPLATE
<p class="alert alert-danger"><b>This setting was automatically changed back to None, because people viewing your faucet without reverse proxy were detected</b>. Make sure your reverse proxy is configured correctly.</p>
TEMPLATE;

$curl_warning_template = <<<TEMPLATE
<p class="alert alert-danger">cURL based connection failed, using legacy method. Please set <code>'disable_curl' => true,</code> in <code>config.php</code> file.</p>
TEMPLATE;

$send_coins_success_template = <<<TEMPLATE
<p class="alert alert-success">You sent {{amount}} satoshi to <a href="https://faucetbox.com/check/{{address}}" target="_blank">{{address}}</a>.</p>
<script> $(document).ready(function(){ $('.nav-tabs a[href="#send-coins"]').tab('show'); }); </script>
TEMPLATE;

$send_coins_error_template = <<<TEMPLATE
<p class="alert alert-danger">There was an error while sending {{amount}} satoshi to "{{address}}": <u>{{error}}</u></p>
<script> $(document).ready(function(){ $('.nav-tabs a[href="#send-coins"]').tab('show'); }); </script>
TEMPLATE;

$missing_configs_template = <<<TEMPLATE
<div class="alert alert-warning">
<b>There are missing settings in your config.php file. That's probably because they were added in recent update.</b>
<:: missing_configs ::>
<hr>
</div>
TEMPLATE;

$missing_config_template = <<<TEMPLATE
<hr>
    <ul>
        <li>Name: <:: config_name ::></li>
        <li>Default: <code>$<:: config_name ::> = <:: config_default ::>;</code></li>
        <li><:: config_description ::></li>
    </ul>
TEMPLATE;

$template_updates_template = <<<TEMPLATE
<div class="alert alert-warning">
    <b>Your template file is out of date and won't work with this version of Faucet in a BOX. Here's what you have to do to fix that:</b>
    <:: template_updates ::>
<hr>
</div>
TEMPLATE;

$template_update_template = <<<TEMPLATE
<hr>
    <ul>
        <li><:: message ::></li>
    </ul>
TEMPLATE;

// ****************** END ADMIN TEMPLATES

#reCaptcha template
$recaptcha_template = <<<TEMPLATE
<script src="https://www.google.com/recaptcha/api.js" async defer></script>
<div class="g-recaptcha" data-sitekey="<:: your_site_key ::>"></div>
<noscript>
  <div style="width: 302px; height: 352px;">
    <div style="width: 302px; height: 352px; position: relative;">
      <div style="width: 302px; height: 352px; position: absolute;">
        <iframe src="https://www.google.com/recaptcha/api/fallback?k=<:: your_site_key ::>"
                frameborder="0" scrolling="no"
                style="width: 302px; height:352px; border-style: none;">
        </iframe>
      </div>
      <div style="width: 250px; height: 80px; position: absolute; border-style: none;
                  bottom: 21px; left: 25px; margin: 0px; padding: 0px; right: 25px;">
        <textarea id="g-recaptcha-response" name="g-recaptcha-response"
                  class="g-recaptcha-response"
                  style="width: 250px; height: 80px; border: 1px solid #c1c1c1;
                         margin: 0px; padding: 0px; resize: none;" value="">
        </textarea>
      </div>
    </div>
  </div>
</noscript>
TEMPLATE;

function checkOneclickUpdatePossible($response) {
    global $version;

    $oneclick_update_possible = false;
    if(!empty($response['changelog'][$version]['hashes'])) {
        $hashes = $response['changelog'][$version]['hashes'];
        $oneclick_update_possible = class_exists("ZipArchive");
        foreach($hashes as $file => $hash)  {
            if(strpos($file, 'templates/') === 0)
                continue;
            $oneclick_update_possible &=
                is_writable($file) &&
                sha1_file($file) === $hash;
        }
    }
    return $oneclick_update_possible;
}

function setNewPass() {
    global $sql;
    $alphabet = str_split('qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM1234567890');
    $password = '';
    for($i = 0; $i < 15; $i++)
        $password .= $alphabet[array_rand($alphabet)];
    $hash = crypt($password);
    $sql->query("REPLACE INTO Faucetinabox_Settings VALUES ('password', '$hash')");
    return $password;
}

function randHash($length) {
    $alphabet = str_split('qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM1234567890');
    $hash = '';
    for($i = 0; $i < $length; $i++) {
        $hash .= $alphabet[array_rand($alphabet)];
    }
    return $hash;
}

// check if configured
try {
    $pass = $sql->query("SELECT `value` FROM `Faucetinabox_Settings` WHERE `name` = 'password'")->fetch();
} catch(PDOException $e) {
    $pass = null;
}

function getIP() {
    global $sql;
    $type = $sql->query("SELECT `value` FROM `Faucetinabox_Settings` WHERE `name` = 'reverse_proxy'")->fetch();
    if (!$type) $type = array('none');
    switch ($type[0]) {
        case 'cloudflare':
            $ip = array_key_exists('HTTP_CF_CONNECTING_IP', $_SERVER) ? $_SERVER['HTTP_CF_CONNECTING_IP'] : null;
        break;
        case 'incapsula':
            $ip = array_key_exists('HTTP_INCAP_CLIENT_IP', $_SERVER) ? $_SERVER['HTTP_INCAP_CLIENT_IP'] : null;
        break;
        default:
            $ip = $_SERVER['REMOTE_ADDR'];
    }
    if (empty($ip)) {
        $sql->query("UPDATE `Faucetinabox_Settings` SET `value` = 'none-auto' WHERE `name` = 'reverse_proxy' AND `value` <> 'none' LIMIT 1");
        return $_SERVER['REMOTE_ADDR'];
    }
    return $ip;
}

function is_ssl(){
    if(isset($_SERVER['HTTPS'])){
        if('on' == strtolower($_SERVER['HTTPS']))
            return true;
        if('1' == $_SERVER['HTTPS'])
            return true;
        if(true == $_SERVER['HTTPS'])
            return true;
    }elseif(isset($_SERVER['SERVER_PORT']) && ('443' == $_SERVER['SERVER_PORT'])){
        return true;
    }
    if(isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && strtolower($_SERVER['HTTP_X_FORWARDED_PROTO']) == 'https') {
        return true;
    }
    return false;
}

function ipSubnetCheck ($ip, $network) {
    $network = explode("/", $network);
    $net = $network[0];

    if(count($network) > 1) {
        $mask = $network[1];
    } else {
        $mask = 32;
    }

    $net = ip2long ($net);
    $mask = ~((1 << (32 - $mask)) - 1);

    $ip_net = $ip & $mask;

    return ($ip_net == $net);
}

function banned() {
    trigger_error("Banned: ".getIP());
    http_response_code(500);
    die();
}

function suspicious($server, $comment) {
    if($server) {
        @file_get_contents($server."report/1/".urlencode(getIP())."/".urlencode($comment));
    }
}


if($pass) {
    if(array_key_exists('p', $_GET) && $_GET['p'] == 'logout')
        $_SESSION = array();

    // check db updates
    $dbversion = $sql->query("SELECT `value` FROM `Faucetinabox_Settings` WHERE `name` = 'version'")->fetch();
    if($dbversion) {
        $dbversion = intval($dbversion[0]);
    } else {
        $dbversion = -1;
    }
    foreach($db_updates as $v => $update) {
        if($v > $dbversion) {
            foreach($update as $query) {
                $sql->exec($query);
            }
        }
    }
    if($dbversion < 17) {
        // dogecoin changed from satoshi to doge
        // better clear rewards...
        $c = $sql->query("SELECT `value` FROM `Faucetinabox_Settings` WHERE `name` = 'currency'")->fetch();
        if($c[0] == 'DOGE')
            $sql->exec("UPDATE `Faucetinabox_Settings` SET `value` = '' WHERE name = 'rewards'");
    }
    if(intval($version) > intval($dbversion)) {
        $q = $sql->prepare("UPDATE `Faucetinabox_Settings` SET `value` = ? WHERE `name` = 'version'");
        $q->execute(array($version));
    }

    $security_settings = array();
    $q = $sql->query("SELECT `name`, `value` FROM `Faucetinabox_Settings` WHERE `name` in ('ip_check_server', 'ip_ban_list', 'hostname_ban_list', 'address_ban_list')");
    while($row = $q->fetch()) {
        if(stripos($row["name"], "_list") !== false) {
            $security_settings[$row["name"]] = array();
            if(preg_match_all("/[^,;\s]+/", $row["value"], $matches)) {
                foreach($matches[0] as $m) {
                    $security_settings[$row["name"]][] = $m;
                }
            }
        } else {
            $security_settings[$row["name"]] = $row["value"];
        }
    }

    if(!empty($_POST["mmc"])) {
        $_SESSION["mouse_movement_detected"] = true;
        die();
    }

    if($_SERVER["REQUEST_METHOD"] == "POST") {
        if($security_settings["ip_check_server"]) {
            if(!preg_match("#/$#", $security_settings["ip_check_server"])) {
                $security_settings["ip_check_server"] .= "/";
            }
        }

        // banning
        $ip = ip2long(getIP());
        if($ip) { // only ipv4 supported here
            foreach($security_settings["ip_ban_list"] as $ban) {
                if(ipSubnetCheck($ip, $ban)) {
                    banned();
                }
            }
        }

        if($security_settings["ip_check_server"]) {

            $hostnames = @file_get_contents($security_settings["ip_check_server"].getIP());
            $hostnames = json_decode($hostnames);

            if($hostnames && property_exists($hostnames, "status") && $hostnames->status == 200) {
                if(property_exists($hostnames, 'suggestion') && $hostnames->suggestion == "deny") {
                    banned();
                }

                if(property_exists($hostnames, 'hostnames')) {
                    foreach($security_settings["hostname_ban_list"] as $ban) {
                        foreach($hostnames->hostnames as $hostname) {
                            if(stripos($hostname, $ban) !== false) {
                                banned();
                            }
                        }
                    }
                }

            }
        }
        $fake_address_input_used = false;
        if(!empty($_POST["address"])) {
            $fake_address_input_used = true;
        }
    }


    if(!$disable_admin_panel && array_key_exists('p', $_GET) && $_GET['p'] == 'admin') {
        $invalid_key = false;
        if (array_key_exists('password', $_POST)) {
            if ($pass[0] == crypt($_POST['password'], $pass[0])) {
                $_SESSION["$session_prefix-logged_in"] = true;
                header("Location: ?p=admin&session_check=0");
                die();
            } else {
                $admin_login_template = $login_error_template.$admin_login_template;
            }
        }
        if (array_key_exists("session_check", $_GET)) {
            if (array_key_exists("$session_prefix-logged_in", $_SESSION)) {
                header("Location: ?p=admin");
                die();
            } else {
                //show alert on login screen
                $admin_login_template = $session_error_template.$admin_login_template;
            }
        }

        if(array_key_exists("$session_prefix-logged_in", $_SESSION)) { // logged in to admin page

            //ajax
            if (array_key_exists("action", $_POST)) {

                header("Content-type: application/json");

                $response = ["status" => 404];

                switch ($_POST["action"]) {
                    case "check_referrals":

                        $referral = array_key_exists("referral", $_POST) ? trim($_POST["referral"]) : "";

                        $response["status"] = 200;
                        $response["addresses"] = [];

                        if (strlen($referral) > 0) {

                            $q = $sql->prepare("SELECT `a`.`address`, `r`.`address` FROM `Faucetinabox_Refs` `r` LEFT JOIN `Faucetinabox_Addresses` `a` ON `r`.`id` = `a`.`ref_id` WHERE `r`.`address` LIKE ? ORDER BY `a`.`last_used` DESC");
                            $q->execute(["%".$referral."%"]);
                            while ($row = $q->fetch()) {
                                $response["addresses"][] = [
                                    "address" => $row[0],
                                    "referral" => $row[1],
                                ];
                            }

                        }

                    break;
                }

                die(json_encode($response));

            }

            if (array_key_exists('task', $_POST) && $_POST['task'] == 'oneclick-update') {
                function recurse_copy($copy_as_new,$src,$dst) {
                    $dir = opendir($src);
                    @mkdir($dst);
                    while(false !== ( $file = readdir($dir)) ) {
                        if (( $file != '.' ) && ( $file != '..' )) {
                            if ( is_dir($src . '/' . $file) ) {
                                recurse_copy($copy_as_new, $src . '/' . $file,$dst . '/' . $file);
                            }
                            else {
                                $dstfile = $dst.'/'.$file;
                                if(in_array(realpath($dstfile), $copy_as_new))
                                    $dstfile .= ".new";
                                if(!copy($src . '/' . $file,$dstfile)) {
                                    return false;
                                }
                            }
                        }
                    }
                    closedir($dir);
                    return true;
                }
                function rrmdir($dir) {
                  if (is_dir($dir)) {
                    $objects = scandir($dir);
                    foreach ($objects as $object) {
                      if ($object != "." && $object != "..") {
                        if (filetype($dir."/".$object) == "dir") rrmdir($dir."/".$object); else unlink($dir."/".$object);
                      }
                    }
                    reset($objects);
                    rmdir($dir);
                  }
                }

                ini_set('display_errors', true);
                error_reporting(-1);
                $fb = new SpareSomeCoins(null, null, $connection_options);
                $response = $fb->fiabVersionCheck();
                if(empty($response['version']) || $response['version'] == $version || !checkOneclickUpdatePossible($response)) {
                    header("Location: ?p=admin&update_status=fail");
                    die();
                }

                $url = $response["url"];
                if($url[0] == '/') $url = "https:$url";
                $url .= "?update=auto";

                if(!file_put_contents('update.zip', fopen($url, 'rb'))) {
                    header("Location: ?p=admin&update_status=fail");
                    die();
                }

                $zip = new ZipArchive();
                if(!$zip->open('update.zip')) {
                    unlink('update.zip');
                    header("Location: ?p=admin&update_status=fail");
                    die();
                }

                if(!$zip->extractTo('./')) {
                    unlink('update.zip');
                    header("Location: ?p=admin&update_status=fail");
                    die();
                }

                $dir = trim($zip->getNameIndex(0), '/');
                $zip->close();
                unlink('update.zip');
                unlink("$dir/config.php");

                $modified_files = [];
                foreach($response['changelog'][$version]['hashes'] as $file => $hash) {
                    if(strpos($file, 'templates/') === 0 &&
                       sha1_file($file) !== $hash
                    ) {
                        $modified_files[] = realpath($file);
                    }
                }
                if(!recurse_copy($modified_files, $dir, '.')) {
                    header("Location: ?p=admin&update_status=fail");
                    die();
                }
                rrmdir($dir);
                header("Location: ?p=admin&update_status=success&new_files=".count($modified_files));
                die();
            }

            if (
                array_key_exists("update_status", $_GET) &&
                in_array($_GET["update_status"], ["success", "fail"])
            ) {
                if ($_GET["update_status"] == "success") {
                    $oneclick_update_alert = $oneclick_update_success_template;
                } else {
                    $oneclick_update_alert = $oneclick_update_fail_template;
                }
            } else {
                $oneclick_update_alert = "";
            }

            if (array_key_exists("encoded_data", $_POST)) {
                $data = base64_decode($_POST["encoded_data"]);
                if ($data) {
                    parse_str($data, $tmp);
                    $_POST = array_merge($_POST, $tmp);
                }
            }

            if(array_key_exists('get_options', $_POST)) {
                if(file_exists("templates/{$_POST["get_options"]}/setup.php")) {
                    require_once("templates/{$_POST["get_options"]}/setup.php");
                    die(getTemplateOptions($sql, $_POST['get_options']));
                } else {
                    die('<p>No template defined options available.</p>');
                }
            } else if(
                array_key_exists("reset", $_POST) &&
                array_key_exists("factory_reset_confirm", $_POST) &&
                $_POST["factory_reset_confirm"] == "on"
            ) {
                $sql->exec("DELETE FROM Faucetinabox_Settings WHERE name NOT LIKE '%key%' AND name != 'password'");
                $sql->exec($default_data_query);
            }
            $q = $sql->prepare("SELECT value FROM Faucetinabox_Settings WHERE name = ?");
            $q->execute(array('apikey'));
            $apikey = $q->fetch();
            $apikey = $apikey[0];
            $q->execute(array('currency'));
            $currency = $q->fetch();
            $currency = $currency[0];
            $fb = new SpareSomeCoins($apikey, $currency, $connection_options);
            $currencies = $fb->getCurrencies();
            $connection_error = '';
            $curl_warning = '';
            $missing_configs_info = '';
            if(!empty($missing_configs)) {
                $list = '';
                foreach($missing_configs as $missing_config) {
                    $list .= str_replace(array("<:: config_name ::>", "<:: config_default ::>", "<:: config_description ::>"), array($missing_config['name'], $missing_config['default'], $missing_config['desc']), $missing_config_template);
                }
                $missing_configs_info = str_replace("<:: missing_configs ::>", $list, $missing_configs_template);
            }
            if($fb->curl_warning) {
                $curl_warning = $curl_warning_template;
            }
            if(!$currencies) {
                $currencies = array('BTC', 'LTC', 'DOGE', 'PPC', 'XPM', 'DASH');
            }
            $send_coins_message = '';
            if(array_key_exists('send_coins', $_POST)) {

                $amount = array_key_exists('send_coins_amount', $_POST) ? intval($_POST['send_coins_amount']) : 0;
                $address = array_key_exists('send_coins_address', $_POST) ? trim($_POST['send_coins_address']) : '';

                $fb = new SpareSomeCoins($apikey, $currency, $connection_options);
                $ret = $fb->send($address, $amount);

                if ($ret['success']) {
                    $send_coins_message = str_replace(array('{{amount}}','{{address}}'), array($amount,$address), $send_coins_success_template);
                } else {
                    $send_coins_message = str_replace(array('{{amount}}','{{address}}','{{error}}'), array($amount,$address,$ret['message']), $send_coins_error_template);
                }

            }
            $changes_saved = "";
            $nastyhosts_not_allowed_alert = "";
            if(array_key_exists('save_settings', $_POST)) {
                $currency = $_POST['currency'];
                $fb = new SpareSomeCoins($_POST['apikey'], $currency, $connection_options);
                $ret = $fb->getBalance();

                if($ret['status'] == 403) {
                    $invalid_key = true;
                } elseif($ret['status'] == 405) {
                    $sql->query("UPDATE Faucetinabox_Settings SET `value` = 0 WHERE name = 'balance'");
                } elseif(array_key_exists('balance', $ret)) {
                    $q = $sql->prepare("UPDATE Faucetinabox_Settings SET `value` = ? WHERE name = 'balance'");
                    if($currency != 'DOGE')
                        $q->execute(array($ret['balance']));
                    else
                        $q->execute(array($ret['balance_bitcoin']));
                }

                $q = $sql->prepare("INSERT IGNORE INTO Faucetinabox_Settings (`name`, `value`) VALUES (?, ?)");
                $template = $_POST["template"];
                preg_match_all('/\$data\[([\'"])(custom_(?:(?!\1).)*)\1\]/', file_get_contents("templates/$template/index.php"), $matches);
                foreach($matches[2] as $box)
                    $q->execute(array("{$box}_$template", ''));


                if (array_key_exists("ip_check_server", $_POST) && !empty($_POST["ip_check_server"])) {

                    $hostnames = @file_get_contents($_POST["ip_check_server"].getIP());
                    $hostnames = json_decode($hostnames);

                    if ($hostnames && property_exists($hostnames, "status") && $hostnames->status == 200) {
                        if (property_exists($hostnames, 'suggestion') && $hostnames->suggestion == "deny") {
                            $nastyhosts_not_allowed_alert = $nastyhosts_not_allowed_template;
                            $_POST["ip_check_server"] = "";
                        }
                    }

                }


                $q = $sql->prepare("UPDATE Faucetinabox_Settings SET value = ? WHERE name = ?");
                $ipq = $sql->prepare("INSERT INTO Faucetinabox_Pages (url_name, name, html) VALUES (?, ?, ?)");
                $sql->exec("DELETE FROM Faucetinabox_Pages");
                foreach($_POST as $k => $v) {
                    if($k == 'apikey' && $invalid_key)
                        continue;
                    if($k == 'pages') {
                        foreach($_POST['pages'] as $p) {
                            $url_name = strtolower(preg_replace("/[^A-Za-z0-9_\-]/", '', $p["name"]));
                            $i = 0;
                            $success = false;
                            while(!$success) {
                                try {
                                    if($i)
                                        $ipq->execute(array($url_name.'-'.$i, $p['name'], $p['html']));
                                    else
                                        $ipq->execute(array($url_name, $p['name'], $p['html']));
                                    $success = true;
                                } catch(PDOException $e) {
                                    $i++;
                                }
                            }
                        }
                        continue;
                    }
                    $q->execute(array($v, $k));
                }
                if (!array_key_exists('block_adblock', $_POST)) $q->execute(array('', 'block_adblock'));

                $changes_saved = $changes_saved_template;
            }
            $page = str_replace('<:: content ::>', $admin_template, $master_template);
            $query = $sql->query("SELECT name, value FROM Faucetinabox_Settings");
            while($row = $query->fetch()) {
                if($row[0] == 'template') {
                    if(file_exists("templates/{$row[1]}/index.php")) {
                        $current_template = $row[1];
                    } else {
                        $templates = glob("templates/*");
                        if($templates)
                            $current_template = substr($templates[0], strlen('templates/'));
                        else
                            die(str_replace("<:: content ::>", "<div class='alert alert-danger' role='alert'>No templates found! Please reinstall your faucet.</div>", $master_template));
                    }
                } else {
                    if ($row[0] == 'reverse_proxy') {
                        if ($row[1] == 'none-auto') {
                            $reverse_proxy_changed_alert = $reverse_proxy_changed_alert_template;
                            $row[1] = 'none';
                        } else {
                            $reverse_proxy_changed_alert = '';
                        }
                        $page = str_replace('<:: reverse_proxy_changed_alert ::>', $reverse_proxy_changed_alert, $page);
                    }
                    if($row[0] == 'block_adblock') {
                        $row[1] = $row[1] == 'on' ? 'checked' : '';
                    }
                    $page = str_replace("<:: {$row[0]} ::>", $row[1], $page);
                }
            }


            $templates = '';
            foreach(glob("templates/*") as $template) {
                $template = basename($template);
                if($template == $current_template) {
                    $templates .= "<option selected>$template</option>";
                } else {
                    $templates .= "<option>$template</option>";
                }
            }
            $page = str_replace('<:: templates ::>', $templates, $page);
            $page = str_replace('<:: current_template ::>', $current_template, $page);


            if(file_exists("templates/{$current_template}/setup.php")) {
                require_once("templates/{$current_template}/setup.php");
                $page = str_replace('<:: template_options ::>', getTemplateOptions($sql, $current_template), $page);
            } else {
                $page = str_replace('<:: template_options ::>', '<p>No template defined options available.</p>', $page);
            }

            $template_string = file_get_contents("templates/{$current_template}/index.php");
            $template_updates_info = '';
            foreach($template_updates as $update) {
                if(!preg_match($update["test"], $template_string)) {
                    $template_updates_info .= str_replace("<:: message ::>", $update["message"], $template_update_template);
                }
            }
            if(!empty($template_updates_info)) {
                $template_updates_info = str_replace("<:: template_updates ::>", $template_updates_info, $template_updates_template);
            }

            $q = $sql->query("SELECT name, html FROM Faucetinabox_Pages ORDER BY id");
            $pages = '';
            $pages_nav = '';
            $i = 1;
            while($userpage = $q->fetch()) {
                $html = htmlspecialchars($userpage['html']);
                $name = htmlspecialchars($userpage['name']);
                $pages .= str_replace(array('<:: i ::>', '<:: page_name ::>', '<:: html ::>'),
                                      array($i, $name, $html), $page_form_template);
                $pages_nav .= str_replace('<:: i ::>', $i, $page_nav_template);
                ++$i;
            }
            $page = str_replace('<:: pages ::>', $pages, $page);
            $page = str_replace('<:: pages_nav ::>', $pages_nav, $page);
            $currencies_select = "";
            foreach($currencies as $c) {
                if($currency == $c)
                    $currencies_select .= "<option value='$c' selected>$c</option>";
                else
                    $currencies_select .= "<option value='$c'>$c</option>";
            }
            $page = str_replace('<:: currency ::>', $currency, $page);
            $page = str_replace('<:: currencies ::>', $currencies_select, $page);


            if($invalid_key)
                $page = str_replace('<:: invalid_key ::>', $invalid_key_error_template, $page);
            else
                $page = str_replace('<:: invalid_key ::>', '', $page);

            $page = str_replace('<:: page_form_template ::>',
                                json_encode($page_form_template),
                                $page);
            $page = str_replace('<:: page_nav_template ::>',
                                json_encode($page_nav_template),
                                $page);

            $new_files = [];
            foreach (new RecursiveIteratorIterator (new RecursiveDirectoryIterator ('templates')) as $file) {
                $file = $file->getPathname();
                if(substr($file, -4) == ".new") {
                    $new_files[] = $file;
                }
            }

            if($new_files) {
                $new_files = implode("\n", array_map(function($v) { return "<li>$v</li>"; }, $new_files));
                $new_files = str_replace("<:: new_files ::>", $new_files, $new_files_template);
            } else {
                $new_files = "";
            }
            $page = str_replace("<:: new_files ::>", $new_files, $page);

            $response = $fb->fiabVersionCheck();
            $oneclick_update_possible = checkOneclickUpdatePossible($response);
            if(!$connection_error && $response['version'] && $version < intval($response["version"])) {
                $page = str_replace('<:: version_check ::>', $new_version_template, $page);
                $changelog = '';
                foreach($response['changelog'] as $v => $changes) {
                    $changelog_entries = array_map(function($entry) {
                        return "<li>$entry</li>";
                    }, $changes['changelog']);
                    $changelog_entries = implode("", $changelog_entries);
                    if(intval($v) > $version) {
                        $changelog .= "<p>Changes in r$v (${changes['released']}): <ul>${changelog_entries}</ul></p>";
                    }
                }
                $page = str_replace(array('<:: url ::>', '<:: version ::>', '<:: changelog ::>'), array($response['url'], $response['version'], $changelog), $page);
                if($oneclick_update_possible) {
                    $page = str_replace('<:: oneclick_update_button ::>', $oneclick_update_button_template, $page);
                } else {
                    $page = str_replace('<:: oneclick_update_button ::>', '', $page);
                }
            } else {
                $page = str_replace('<:: version_check ::>', '', $page);
            }
            $page = str_replace('<:: connection_error ::>', $connection_error, $page);
            $page = str_replace('<:: curl_warning ::>', $curl_warning, $page);
            $page = str_replace('<:: send_coins_message ::>', $send_coins_message, $page);
            $page = str_replace('<:: missing_configs ::>', $missing_configs_info, $page);
            $page = str_replace('<:: template_updates ::>', $template_updates_info, $page);
            $page = str_replace('<:: changes_saved ::>', $changes_saved, $page);
            $page = str_replace('<:: oneclick_update_alert ::>', $oneclick_update_alert, $page);
            $page = str_replace('<:: nastyhosts_not_allowed ::>', $nastyhosts_not_allowed_alert, $page);
            die($page);
        } else {
            // requested admin page without session
            $page = str_replace('<:: content ::>', $admin_login_template, $master_template);
            die($page);
        }
    } elseif(!$disable_admin_panel && array_key_exists('p', $_GET) && $_GET['p'] == 'password-reset') {
        $error = "";
        if(array_key_exists('dbpass', $_POST)) {
            if($_POST['dbpass'] == $dbpass) {
                $password = setNewPass();
                $page = str_replace('<:: content ::>', $pass_template, $master_template);
                $page = str_replace('<:: password ::>', $password, $page);
                die($page);
            } else {
                $error = "<p class='alert alert-danger' role='alert'>Wrong database password</p>";
            }
        }
        $page = str_replace('<:: content ::>', $error.$pass_reset_template, $master_template);
        die($page);
    } else {
        // show main page
        $q = $sql->query("SELECT value FROM Faucetinabox_Settings WHERE name = 'template'");
        $template = $q->fetch();
        $template = $template[0];
        if(!file_exists("templates/{$template}/index.php")) {
            $templates = glob("templates/*");
            if($templates)
                $template = substr($templates[0], strlen("templates/"));
            else
                die(str_replace('<:: content ::>', "<div class='alert alert-danger' role='alert'>No templates found!</div>", $master_template));
        }

        if(array_key_exists("HTTPS", $_SERVER) && $_SERVER["HTTPS"])
            $protocol = "https://";
        else
            $protocol = "http://";

        if (array_key_exists('address_input_name', $_SESSION) && array_key_exists($_SESSION['address_input_name'], $_POST)) {
            $_POST['address'] = $_POST[$_SESSION['address_input_name']];
        } else {
            if($display_errors && $_SERVER['REQUEST_METHOD'] == "POST") {
                if(array_key_exists('address_input_name', $_SESSION)) {
                    trigger_error("Post request, but session is invalid.");
                } else {
                    trigger_error("Post request, but invalid address input name.");
                }
            }
            unset($_POST['address']);
        }


        $data = array(
            "paid" => false,
            "disable_admin_panel" => $disable_admin_panel,
            "address" => "",
            "captcha_valid" => !array_key_exists('address', $_POST),
            "captcha" => false,
            "enabled" => false,
            "error" => false,
            "reflink" => $protocol.$_SERVER['HTTP_HOST'].strtok($_SERVER['REQUEST_URI'], '?').'?r='
        );
        if(array_key_exists('address', $_POST)) {
            $data["reflink"] .= $_POST['address'];
        } else if (array_key_exists('address', $_COOKIE)) {
            $data["reflink"] .= $_COOKIE['address'];
            $data["address"] = $_COOKIE['address'];
        } else {
            $data["reflink"] .= 'Your_Address';
        }


        $q = $sql->query("SELECT name, value FROM Faucetinabox_Settings WHERE name <> 'password'");

        while($row = $q->fetch()) {
            $data[$row[0]] = $row[1];
        }

        if(time() - $data['last_balance_check'] > 60*10) {
            $fb = new SpareSomeCoins($data['apikey'], $data['currency'], $connection_options);
            $ret = $fb->getBalance();
            if(array_key_exists('balance', $ret)) {
                if($data['currency'] != 'DOGE')
                    $balance = $ret['balance'];
                else
                    $balance = $ret['balance_bitcoin'];
                $q = $sql->prepare("UPDATE Faucetinabox_Settings SET value = ? WHERE name = ?");
                $q->execute(array(time(), 'last_balance_check'));
                $q->execute(array($balance, 'balance'));
                $data['balance'] = $balance;
                $data['last_balance_check'] = time();
            }
        }

        $data['unit'] = 'satoshi';
        if($data["currency"] == 'DOGE')
            $data["unit"] = 'DOGE';


        #MuliCaptcha: Firstly check chosen captcha system
        $captcha = array('available' => array(), 'selected' => null);
        if ($data['solvemedia_challenge_key'] && $data['solvemedia_verification_key'] && $data['solvemedia_auth_key']) {
            $captcha['available'][] = 'SolveMedia';
        }
        if ($data['recaptcha_public_key'] && $data['recaptcha_private_key']) {
            $captcha['available'][] = 'reCaptcha';
        }
        if ($data['ayah_publisher_key'] && $data['ayah_scoring_key']) {
            $captcha['available'][] = 'AreYouAHuman';
        }
        if ($data['funcaptcha_public_key'] && $data['funcaptcha_private_key']) {
            $captcha['available'][] = 'FunCaptcha';
        }

        #MuliCaptcha: Secondly check if user switched captcha or choose default
        if (array_key_exists('cc', $_GET) && in_array($_GET['cc'], $captcha['available'])) {
            $captcha['selected'] = $captcha['available'][array_search($_GET['cc'], $captcha['available'])];
            $_SESSION["$session_prefix-selected_captcha"] = $captcha['selected'];
        } elseif (array_key_exists("$session_prefix-selected_captcha", $_SESSION) && in_array($_SESSION["$session_prefix-selected_captcha"], $captcha['available'])) {
            $captcha['selected'] = $_SESSION["$session_prefix-selected_captcha"];
        } else {
            if($captcha['available'])
                $captcha['selected'] = $captcha['available'][0];
            if (in_array($data['default_captcha'], $captcha['available'])) {
                $captcha['selected'] = $data['default_captcha'];
            } else if($captcha['available']) {
                $captcha['selected'] = $captcha['available'][0];
            }
        }



        #MuliCaptcha: And finally handle chosen captcha system
        switch ($captcha['selected']) {
            case 'SolveMedia':
                require_once("libs/solvemedialib.php");
                $data["captcha"] = solvemedia_get_html($data["solvemedia_challenge_key"], null, is_ssl());
                if (array_key_exists('address', $_POST)) {
                    $resp = solvemedia_check_answer(
                        $data['solvemedia_verification_key'],
                        getIP(),
                        (array_key_exists('adcopy_challenge', $_POST) ? $_POST['adcopy_challenge'] : ''),
                        (array_key_exists('adcopy_response', $_POST) ? $_POST['adcopy_response'] : ''),
                        $data["solvemedia_auth_key"]
                    );
                    $data["captcha_valid"] = $resp->is_valid;
                }
            break;
            case 'reCaptcha':
                $data["captcha"] = str_replace('<:: your_site_key ::>', $data["recaptcha_public_key"], $recaptcha_template);
                if (array_key_exists('address', $_POST)) {
                    $url = 'https://www.google.com/recaptcha/api/siteverify?secret='.$data["recaptcha_private_key"].'&response='.(array_key_exists('g-recaptcha-response', $_POST) ? $_POST["g-recaptcha-response"] : '').'&remoteip='.getIP();
                    $resp = json_decode(file_get_contents($url), true);
                    $data['captcha_valid'] = $resp['success'];
                }
            break;
            case 'AreYouAHuman':
                require_once("libs/ayahlib.php");
                $ayah = new AYAH(array(
                    'publisher_key' => $data['ayah_publisher_key'],
                    'scoring_key' => $data['ayah_scoring_key'],
                    'web_service_host' => 'ws.areyouahuman.com',
                    'debug_mode' => false,
                    'use_curl' => !($connection_options['disable_curl'])
                ));
                $data['captcha'] = $ayah->getPublisherHTML();
                if (array_key_exists('address', $_POST)) {
                    $score = $ayah->scoreResult();
                    $data['captcha_valid'] = $score;
                }
            break;
            case 'FunCaptcha':
                require_once("libs/funcaptcha.php");
                $funcaptcha = new FUNCAPTCHA();

                $data["captcha"] =  $funcaptcha->getFunCaptcha($data["funcaptcha_public_key"]);

                if (array_key_exists('address', $_POST)) {
                    $data['captcha_valid'] =  $funcaptcha->checkResult($data["funcaptcha_private_key"]);
                }
            break;
        }

        $data['captcha_info'] = $captcha;

        if($data['captcha'] && $data['apikey'] && $data['rewards'])
            $data['enabled'] = true;


        // check if ip eligible
        $q = $sql->prepare("SELECT TIMESTAMPDIFF(MINUTE, last_used, CURRENT_TIMESTAMP()) FROM Faucetinabox_IPs WHERE ip = ?");
        $q->execute(array(getIP()));
        if ($time = $q->fetch()) {
            $time = intval($time[0]);
            $required = intval($data['timer']);
            $data['time_left'] = ($required-$time).' minutes';
            $data['eligible'] = $time >= intval($data['timer']);
        } else {
            $data["eligible"] = true;
        }

        $rewards = explode(',', $data['rewards']);
        $total_weight = 0;
        $nrewards = array();
        foreach($rewards as $reward) {
            $reward = explode("*", trim($reward));
            if(count($reward) < 2) {
                $reward[1] = $reward[0];
                $reward[0] = 1;
            }
            $total_weight += intval($reward[0]);
            $nrewards[] = $reward;
        }
        $rewards = $nrewards;
        if(count($rewards) > 1) {
            $possible_rewards = array();
            foreach($rewards as $r) {
                $chance_per = 100 * $r[0]/$total_weight;
                if($chance_per < 0.1)
                    $chance_per = '< 0.1%';
                else
                    $chance_per = round(floor($chance_per*10)/10, 1).'%';

                $possible_rewards[] = $r[1]." ($chance_per)";
            }
        } else {
            $possible_rewards = array($rewards[0][1]);
        }

        $data['address_eligible'] = true;

        if (array_key_exists('address', $_POST) &&
           $data['captcha_valid'] &&
           $data['enabled'] &&
           $data['eligible']
        ) {

            $q = $sql->prepare("SELECT TIMESTAMPDIFF(MINUTE, last_used, CURRENT_TIMESTAMP()) FROM Faucetinabox_Addresses WHERE `address` = ?");
            $q->execute(array(trim($_POST['address'])));
            if ($time = $q->fetch()) {
                $time = intval($time[0]);
                $required = intval($data['timer']);
                $data['time_left'] = ($required-$time).' minutes';
                $eligible = $time >= intval($data['timer']);
            } else {
                $eligible = true;
            }
            $data['address_eligible'] = $eligible;
            if($eligible) {
                $r = mt_rand()/mt_getrandmax();
                $t = 0;
                foreach($rewards as $reward) {
                    $t += intval($reward[0])/$total_weight;
                    if($t > $r) {
                        break;
                    }
                }

                if (strpos($reward[1], '-') !== false) {
                    $reward_range = explode('-', $reward[1]);
                    $from = floatval($reward_range[0]);
                    $to = floatval($reward_range[1]);
                    $reward = mt_rand($from, $to);
                } else {
                    $reward = floatval($reward[1]);
                }
                if($data["currency"] == "DOGE")
                    $reward = $reward * 100000000;

                $q = $sql->prepare("SELECT balance FROM Faucetinabox_Refs WHERE address = ?");
                $q->execute(array(trim($_POST["address"])));
                if($b = $q->fetch()) {
                    $refbalance = floatval($b[0]);
                } else {
                    $refbalance = 0;
                }
                $fb = new SpareSomeCoins($data["apikey"], $data["currency"], $connection_options);
                $address = trim($_POST["address"]);
                if (empty($address)) {
                    $ret = array(
                        "success" => false,
                        "message" => "Invalid address.",
                        "html" => "<div class=\"alert alert-danger\">Invalid address.</div>"
                    );
                } else if (in_array($address, $security_settings["address_ban_list"])) {
                    $ret = array(
                        "success" => false,
                        "message" => "Unknown error.",
                        "html" => "<div class=\"alert alert-danger\">Unknown error.</div>"
                    );
                } else {
                    $ret = $fb->send($address, $reward);
                }
                if($ret["success"] && $refbalance > 0)
                    $ret = $fb->sendReferralEarnings(trim($_POST["address"]), $refbalance);
                if($ret['success']) {
                    setcookie('address', trim($_POST['address']), time() + 60*60*24*60);
                    if(array_key_exists('balance', $ret)) {
                        $q = $sql->prepare("UPDATE Faucetinabox_Settings SET `value` = ? WHERE `name` = 'balance'");

                        if($data['unit'] == 'satoshi')
                            $data['balance'] = $ret['balance'];
                        else
                            $data['balance'] = $ret['balance_bitcoin'];
                        $q->execute(array($data['balance']));
                    }

                    // handle refs
                    // deduce balance
                    $q = $sql->prepare("UPDATE Faucetinabox_Refs SET balance = balance - ? WHERE address = ?");
                    $q->execute(array($refbalance, trim($_POST['address'])));
                    // add balance
                    if(array_key_exists('r', $_GET) && trim($_GET['r']) != trim($_POST["address"])) {
                        $q = $sql->prepare("INSERT IGNORE INTO Faucetinabox_Refs (address) VALUES (?)");
                        $q->execute(array(trim($_GET["r"])));
                        $q = $sql->prepare("INSERT IGNORE INTO Faucetinabox_Addresses (`address`, `ref_id`, `last_used`) VALUES (?, (SELECT id FROM Faucetinabox_Refs WHERE address = ?), CURRENT_TIMESTAMP())");
                        $q->execute(array(trim($_POST['address']), trim($_GET['r'])));
                    }
                    $refamount = floatval($data['referral'])*$reward/100;
                    $q = $sql->prepare("SELECT address FROM Faucetinabox_Refs WHERE id = (SELECT ref_id FROM Faucetinabox_Addresses WHERE address = ?)");
                    $q->execute(array(trim($_POST['address'])));
                    if($ref = $q->fetch()) {
                        if(!in_array(trim($ref[0]), $security_settings['address_ban_list'])) {
                            $fb->sendReferralEarnings(trim($ref[0]), $refamount);
                        }
                    }

                    if($refbalance > 0) {
                        $data['paid'] = '<div class="alert alert-success">'.htmlspecialchars($reward).' '.$unit.' + '.htmlspecialchars($refbalance).' '.$unit.' for referrals was sent to <a target="_blank" href="https://sparesomecoins.com/check/'.rawurlencode(trim($_POST["address"])).'">your SpareSomeCoins.com address</a>.</div>';
                    } else {
                        if($data['unit'] == 'satoshi')
                            $data['paid'] = $ret['html'];
                        else
                            $data['paid'] = $ret['html_coin'];
                    }
                } else {
                    $data['error'] = $ret['html'];
                }
                if($ret['success']) {
                    $q = $sql->prepare("INSERT INTO Faucetinabox_IPs (`ip`, `last_used`) VALUES (?, CURRENT_TIMESTAMP()) ON DUPLICATE KEY UPDATE `last_used` = CURRENT_TIMESTAMP()");
                    $q->execute(array(getIP()));
                    $q = $sql->prepare("INSERT INTO Faucetinabox_Addresses (`address`, `last_used`) VALUES (?, CURRENT_TIMESTAMP()) ON DUPLICATE KEY UPDATE `last_used` = CURRENT_TIMESTAMP()");
                    $q->execute(array(trim($_POST["address"])));

                    // suspicious checks
                    $q = $sql->query("SELECT value FROM Faucetinabox_Settings WHERE name = 'template'");
                    if($r = $q->fetch()) {
                        if(stripos(file_get_contents('templates/'.$r[0].'/index.php'), 'libs/mmc.js') !== FALSE) {
                            if($fake_address_input_used || !empty($_POST["honeypot"])) {
                                suspicious($security_settings["ip_check_server"], "honeypot");
                            }

                            if(empty($_SESSION["mouse_movement_detected"])) {
                                suspicious($security_settings["ip_check_server"], "mmc");
                            }
                        }
                    }
                }
            }
        }

        if(!$data['enabled'])
            $page = 'disabled';
        elseif($data['paid'])
            $page = 'paid';
        elseif($data['eligible'] && $data['address_eligible'])
            $page = 'eligible';
        else
            $page = 'visit_later';
        $data['page'] = $page;

        $_SESSION['address_input_name'] = randHash(rand(25,35));
        $data['address_input_name'] = $_SESSION['address_input_name'];

        $data['rewards'] = implode(', ', $possible_rewards);

        $q = $sql->query("SELECT url_name, name FROM Faucetinabox_Pages ORDER BY id");
        $data["user_pages"] = $q->fetchAll();

        $allowed = array("page", "name", "rewards", "short", "error", "paid", "captcha_valid", "captcha", "captcha_info", "time_left", "referral", "reflink", "template", "user_pages", "timer", "unit", "address", "balance", "disable_admin_panel", "address_input_name", "block_adblock", "button_timer");

        preg_match_all('/\$data\[([\'"])(custom_(?:(?!\1).)*)\1\]/', file_get_contents("templates/$template/index.php"), $matches);
        foreach(array_unique($matches[2]) as $box) {
            $key = "{$box}_$template";
            if(!array_key_exists($key, $data)) {
                $data[$key] = '';
            }
            $allowed[] = $key;
        }

        foreach(array_keys($data) as $key) {
            if(!(in_array($key, $allowed))) {
                unset($data[$key]);
            }
        }

        foreach(array_keys($data) as $key) {
            if(array_key_exists($key, $data) && strpos($key, 'custom_') === 0) {
                $data[substr($key, 0, strlen($key) - strlen($template) - 1)] = $data[$key];
                unset($data[$key]);
            }
        }

        if(array_key_exists('p', $_GET)) {
            if(!in_array($_GET['p'], array('logout'))) {
                $q = $sql->prepare("SELECT url_name, name, html FROM Faucetinabox_Pages WHERE url_name = ?");
                $q->execute(array($_GET['p']));
                if($page = $q->fetch()) {
                    $data['page'] = 'user_page';
                    $data['user_page'] = $page;
                } elseif(in_array($_GET['p'], array('admin', 'password-reset'))) {
                    $data['error'] = "<div class='alert alert-danger'>That page is disabled in config.php file!</div>";
                } else {
                    $data['error'] = "<div class='alert alert-danger'>That page doesn't exist!</div>";
                }
            }
        }

        $data['address'] = htmlspecialchars($data['address']);

        if(!empty($_SESSION["mouse_movement_detected"])) {
            unset($_SESSION["mouse_movement_detected"]);
        }
        require_once('templates/'.$template.'/index.php');
        die();
    }
} else {
    $sql->query($default_data_query);
    $password = setNewPass();
    $page = str_replace('<:: content ::>', $pass_template, $master_template);
    $page = str_replace('<:: password ::>', $password, $page);
    die($page);
}
