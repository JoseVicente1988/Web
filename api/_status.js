module.exports = async (req, res) => {
  res.status(200).json({
    ok: true,
    url: req.url,
    node: process.version,
    env: process.env.VERCEL_ENV || null,
    region: process.env.VERCEL_REGION || null,
    now: new Date().toISOString()
  });
};
