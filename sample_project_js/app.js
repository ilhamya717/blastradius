const express = require("express");
const _ = require("lodash");

const app = express();

app.get("/merge", function mergeHandler(req, res) {
  const result = _.merge({}, req.query);
  res.json(result);
});

function unusedHelper() {
  return _.template("<%= x %>")({ x: 1 });
}

app.listen(3000);
