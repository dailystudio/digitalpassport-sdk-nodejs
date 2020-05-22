module.exports = Object.freeze({

    PARAM_ACCESS_TOKEN: 'access_token',

    responseError: function (code, message, res) {
        let error = {
            code: code,
            message: message
        };

        res.status(code).send(JSON.stringify(error));
    },

});