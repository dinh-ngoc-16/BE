const router = require("express").Router();
const User = require("../models/User");
const Cryptojs = require("crypto-js");
const jwt = require("jsonwebtoken");

//REGISTER
router.post("/register", async (req, res) => {
  const newUser = new User({
    username: req.body.username,
    email: req.body.email,
    password: Cryptojs.AES.encrypt(
      req.body.password,
      process.env.PASS_SEC,
    ).toString(),
  });
  try {
    const saveUser = await newUser.save();
    res.status(201).json(saveUser);
  } catch (err) {
    res.status(500).json(err);
  }
});

//LOGIN

router.post("/login", async (req, res) => {
  try {
    const user = await User.findOne({ username: req.body.username });
    if (!user) {
      res.status(401).json("Wrong Username!");
      return;
    }

    const hashedPassword = Cryptojs.AES.decrypt(
      user.password,
      process.env.PASS_SEC,
    );

    const OriginPassword = hashedPassword.toString(Cryptojs.enc.Utf8);
    if (OriginPassword != req.body.password) {
      res.status(401).json("Wrong password!");
      return;
    }

    const accessToken = jwt.sign(
      {
        id: user.id,
        isAdmin: user.isAdmin,
      },
      process.env.JWT_SEC,
      { expiresIn: "3d" },
    );

    const { password, ...others } = user._doc;

    res.status(200).json({ ...others, accessToken });
  } catch (err) {
    res.status(500).json(err);
  }
});

module.exports = router;
