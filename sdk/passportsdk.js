const express           = require('express');
const session           = require("express-session");
const passport          = require('passport');
const OAuth2Strategy    = require('passport-oauth2');
const rp                = require('request-promise');
const fileStore         = require('session-file-store')(session);
const logger            = require("devbricksx-js").logger;
const sdkcommon         = require("./sdkcommon.js");

PassportEndpoint.prototype.getUserOpenId = async function(accessToken) {
    let openId;
    try {
        let data = await rp({
            method: "GET",
            url:`${this.baseUrl}/v1/userinfo/openid`,
            headers: {
                'Authorization': `Bearer ${accessToken}`
            }
        });

        let o = JSON.parse(data);
        logger.debug(`data: ${JSON.stringify(o)}`);
        if (o && o.uid) {
            openId = o.uid;
        }
    } catch (e) {
        logger.error(`get openId failed: ${e}`);
    }

    logger.info(`openId: ${JSON.stringify(openId)}`);

    return {
        profile: {
            uid: openId
        }
    };
};

PassportEndpoint.prototype.getUserProfile = async function (accessToken) {
    let profile;
    try {
        let data = await rp({
            method: "GET",
            url:`${this._baseUrl}/v1/userinfo/profile`,
            headers: {
                'Authorization': `Bearer ${accessToken}`
            },
        });

        let o = JSON.parse(data);
        logger.debug(`data: ${JSON.stringify(o)}`);
        if (o) {
            profile = o.profile || {};
        }
    } catch (e) {
        logger.error(`get profile failed: ${e}`);
    }

    logger.debug(`profile: ${JSON.stringify(profile)}`);

    return profile;
};

// Used to stuff a piece of information into a cookie
PassportEndpoint.prototype.serializeUser = function (user, done) {
    logger.debug(`serializeUser: user = ${JSON.stringify(user)}`);
    done(null, user);
};

// Used to decode the received cookie and persist session
PassportEndpoint.prototype.deserializeUser = function (user, done) {
    logger.debug(`deserializeUser: user = ${JSON.stringify(user)}`);
    done(null, user);
};

function PassportEndpoint(app, options) {
    options = options || {};

    if (!options.passportUrl) { throw new TypeError('passportUrl is required in options.'); }
    if (!options.clientID) { throw new TypeError('clientID is required in options.'); }
    if (!options.clientSecret) { throw new TypeError('clientSecret is required in options.'); }

    this._baseUrl = options.passportUrl;
    this._https = (options.pkce === true);
    this._localPort = 80;
    if (options.localPort) {
        this._localPort = options.localPort;
    }

    if (options.endpoints) {
        this._endpoints = Object.assign({}, options.endpoints);
    }

    if (options.region) {
        this._region = options.region;
    }

    this._endpoints = this._endpoints || {};
    this._endpoints.login = this._endpoints.login || '/v1/auth/login';
    this._endpoints.logout = this._endpoints.logout || '/v1/auth/logout';
    this._endpoints.error = this._endpoints.error || '/v1/auth/error';
    this._endpoints.callback = this._endpoints.callback || '/v1/auth/callback';

    this._clientId = options.clientID;
    this._clientSecret = options.clientSecret;

    let regionPart = "";
    if (this._region) {
        regionPart = `_${this._region}`;
    }

    let self = this;
    this._oAuth2Strategy = new OAuth2Strategy({
            state: this._https, /* require session and https */
            authorizationURL: `${this._baseUrl}/v1/passport/authorize${regionPart}`,
            tokenURL: `${this._baseUrl}/v1/passport/token`,
            clientID: this._clientId,
            clientSecret: this._clientSecret,
            callbackURL: `${this._https ? "https" : "http"}://localhost:${this._localPort}${this._endpoints.callback}`,
            passReqToCallback: true,
            pkce: this._https
        },
        async function(req, accessToken, refreshToken, profile, done) {
            logger.debug(`accessToken: ${accessToken}`);
            logger.debug(`refreshToken: ${refreshToken}`);
            logger.debug(`profile: ${JSON.stringify(profile)}`);
            logger.debug(`req.user: ${req.user}`);

            let up = await self.getUserProfile(accessToken);

            up.access_token = accessToken;
            up.refresh_token = refreshToken;

            done(null, up);
        });

    passport.use('passport-oauth2', this._oAuth2Strategy);

    passport.serializeUser((user, done) => {
        this.serializeUser(user, done);
    });

    passport.deserializeUser((user, done) => {
        this.deserializeUser(user, done);
    });

    let router = express.Router({});
    router.get(this._endpoints.login,
        function (req, res, next) {
            self._returnTo = req.query.originUrl;
            next();
        },
        passport.authenticate('passport-oauth2',{
            // scope: ['profile']
        }),
        function(req, res) {
            logger.debug(`login penetration:${req.originalUrl}`)
        }
    );

    router.get(this._endpoints.error,
        function (req, res) {
            res.status(500).json({
                error: `authorization failed.`
            });
        }
    );

    router.get(this._endpoints.callback,
        passport.authenticate('passport-oauth2', {
            failureRedirect: self._endpoints.error,
        }),
        function (req, res) {
            if (self._returnTo) {
                logger.debug(`redirect to original url: ${self._returnTo}`);
                res.redirect(self._returnTo);
                delete self._returnTo;
            } else {
                res.end(JSON.stringify({
                    code: 200,
                }));
            }
        }
    );

    router.get(this._endpoints.logout, function(req, res){
        req.logout();
        req.session.destroy();
        req.session = null;
        res.redirect('/');
    });

    app.use(
        session({
            secret: this._clientSecret,
            resave: false,
            saveUninitialized: true,
            store: new fileStore('./sessions/'),
            cookie: {
                secure: this._https
            }
        })
    );

    app.use(passport.initialize()); // Used to initialize passport
    app.use(passport.session()); // Used to persist login sessions

    app.use(router);
    app.use((error, req, res, next) => {
        if (error instanceof OAuth2Strategy.TokenError) { // this is
            logger.error(`error: ${error}`);
            res.status(401).json({
                error: `${error}`
            });
        } else {
            logger.error(error);
            res.status(500).json({});
        }
    });
}

function PassportValidator(options) {
    options = options || {};

    if (!options.passportUrl) { throw new TypeError('passportUrl is required in options.'); }

    this._loginUrl = '/v1/auth/login';
    if (options.loginUrl) {
        this._loginUrl = options.loginUrl;
    }

    logger.debug(`_loginUrl: ${this._loginUrl}`);

    this._baseUrl = options.passportUrl;
}

PassportValidator.prototype.checkAuthorization = async function (req, res, next) {
    logger.debug(`Check if request is authorized, user = ${JSON.stringify(req.user)}`);

    if (req.isAuthenticated()) {
        return next();
    }

    let accessToken = null;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
        logger.debug('Found "Authorization" header');
        // Read the ID Token from the Authorization header.
        accessToken = req.headers.authorization.split('Bearer ')[1];
    } else if (req.query[sdkcommon.PARAM_ACCESS_TOKEN]) {
        logger.debug('Found "Authorization" query parameter');
        accessToken = req.query[sdkcommon.PARAM_ACCESS_TOKEN];
    } else if (req.cookies.__session) {
        logger.debug('Found "__session" cookie');
        accessToken = req.cookies.__session;
    }

    if (!accessToken) {
        let redirectUrl = req.protocol + '://'
            + req.get('host')
            + this._loginUrl
            + '?originUrl=' + req.originalUrl;
        logger.debug(`redirectUrl: ${redirectUrl}`);

        return res.redirect(redirectUrl);
    }

    let decodedToken;
    try {
        let data = await rp({
            method: "POST",
            url:`${this._baseUrl}/v1/passport/verify`,
            body: {
                'access_token': accessToken
            }
        });

        decodedToken = JSON.parse(data);
        logger.debug(`decodedToken: ${JSON.stringify(decodedToken)}`);
    } catch (e) {
        logger.error(`get profile failed: ${e}`);
    }

    if (!decodedToken) {
        return sdkcommon.responseError(401,
            `invalided token`, res);
    }

    req.user = decodedToken;

    return next();
};


// Expose constructor.
module.exports.PassportEndpoint = PassportEndpoint;
module.exports.PassportValidator = PassportValidator;
