function vulnerable(req) {
    eval(req.query.code);
}
