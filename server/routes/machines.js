const
  express = require("express"),
  authMiddleware = require("../middleware/auth.js"),

  Machines = require("../models/Machines.js"),

  router = express.Router();

router.get('', authMiddleware, async (req, res) => {
  const { user } = req.query;

  try {

    const machines = await Machines.find({ owner: user });
    return res.json({ machines });

  } catch (error) {

    return res.status(500).send({
      message: error.message,
      error
    });

  }
});

module.exports = router;
