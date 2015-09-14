var fs = require('fs'),
    qs = require('querystring'),
    xml2js = require('xml2js'),
    http = require('http'),
    https = require('https'),
    urlparse = require('url').parse,
    samlRequestTemplate = fs.readFileSync(__dirname+'/SAML.xml', 'utf8');


var buildSamlRequest = function (params) {
    var key,
        saml = samlRequestTemplate;

    for (key in params) {
        saml = saml.replace('[' + key + ']', params[key])
    }

    return saml;
}

var parseXml = function (xml, callback) {
    var parser = new xml2js.Parser({
        emptyTag: '',  // use empty string as value when tag empty
		explicitArray: false // array is created only if there is more than one child
    });

    parser.on('end', function (js) {
        callback && callback(js)
    });

    parser.parseString(xml);
};

var parseCookie = function (txt) {
    var properties = txt.split('; '),
        cookie = {};

    properties.forEach(function (property, index) {
        var idx = property.indexOf('='),
            name = (idx > 0 ? property.substring(0, idx) : property),
            value = (idx > 0 ? property.substring(idx + 1) : undefined);

        if (index == 0) {
            cookie.name = name,
            cookie.value = value
        } else {
            cookie[name] = value
        }

    })

    return cookie;
};

var parseCookies = function (txts) {
    var cookies = []

    if (txts) {
        txts.forEach(function (txt) {
            var cookie = parseCookie(txt);
            cookies.push(cookie)
        })
    };

    return cookies;
}


var getCookie = function (cookies, name) {
    var cookie,
        i = 0,
        len = cookies.length;

    for (; i < len; i++) {
        cookie = cookies[i]
        if (cookie.name == name) {
            return cookie
        }
    }

    return undefined;

}

function requestToken(params, callback) {
    var samlRequest = buildSamlRequest({
        username: params.username,
        password: params.password,
        endpoint: params.endpoint
    });

    var options = {
        method: 'POST',
        host: params.sts.host,
        path: params.sts.path,
        headers: {
            'Content-Length': samlRequest.length
        }
    };


    var req = https.request(options, function (res) {
        var xml = '';

        res.setEncoding('utf8');
        res.on('data', function (chunk) {
            xml += chunk;
        })

        res.on('end', function () {

            parseXml(xml, function (js) {
				
				var body = js['S:Envelope']['S:Body'];

                // check for errors
                if (body['S:Fault']) { 
                    var error = body['S:Fault']['S:Detail']['psf:error']['psf:internalerror']['psf:text'];
                    callback(error);
                    return; 
                } 

                // extract token
                var token = body['wst:RequestSecurityTokenResponse']['wst:RequestedSecurityToken']['wsse:BinarySecurityToken']['_'];

                // Now we have the token, we need to submit it to SPO
                submitToken({
                    token: token,
                    endpoint: params.endpoint
                }, callback)
            })
        })
    });
    
    req.end(samlRequest);
}

function submitToken(params, callback) {
    var token = params.token,
        url = urlparse(params.endpoint),
        ssl = (url.protocol == 'https:');

    var options = {
        method: 'POST',
        host: url.hostname,
        path: url.path,
        headers: {
            // E accounts require a user agent string
            'User-Agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)',
			'Content-Type': 'application/x-www-form-urlencoded'
        }
    };
	
	if(ssl){
		options.secureOptions = require('constants').SSL_OP_NO_TLSv1_2;
	}
	
    var protocol = (ssl ? https : http);    

    var req = protocol.request(options, function (res) {

        var xml = '';
        res.setEncoding('utf8');
        res.on('data', function (chunk) {
            xml += chunk;
        })

        res.on('end', function () {

            var cookies = parseCookies(res.headers['set-cookie'])

            callback(null, {
                FedAuth: getCookie(cookies, 'FedAuth').value,
                rtFa: getCookie(cookies, 'rtFa').value
            })
        })
    });

    req.end(token);
}


function signin(username, password, callback) {
    var self = this;

    var options = {
        username: username,
        password: password,
        sts: self.sts,
        endpoint: self.url.protocol + '//' + self.url.hostname + self.login
    }

    requestToken(options, function (err, data) {

        if (err) {
            callback(err);
            return;
        }

        self.FedAuth = data.FedAuth;
        self.rtFa = data.rtFa;

        callback(null, data);
    })
}

var SP = {};

// constructor for REST service
SP.RestService = function (url) {
    this.url = urlparse(url);
    this.host = this.url.host;
    this.path = this.url.path;
    this.protocol = this.url.protocol;


    // External Security Token Service for SPO
    this.sts = {
        host: 'login.microsoftonline.com',
        path: '/extSTS.srf'
    };

    // Form to submit SAML token
    this.login = '/_forms/default.aspx?wa=wsignin1.0';


    // SharePoint Odata (REST) service
    this.odatasvc = '/_vti_bin/ListData.svc/';

};

SP.RestService.prototype = {
    signin: signin
};

module.exports = SP;