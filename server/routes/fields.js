const
  express = require("express"),
  authMiddleware = require("../middleware/auth.js"),

  Fields = require("../models/Fields.js"),

  router = express.Router();

router.get('', authMiddleware, async (req, res) => {
  const { user } = req.query;

  try {

    const fields = await Fields.find({ owner: user });
    return res.json({ fields });

  } catch (error) {

    return res.status(500).send({
      message: error.message,
      error
    });

  }
});

module.exports = router;
