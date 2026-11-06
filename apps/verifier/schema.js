import Joi from 'joi';

export const metadataSchema = Joi.object({
  tools: Joi.array().max(20).items(Joi.object({
    toolId: Joi.string().min(1).max(100).required(),
    toolName: Joi.string().min(1).max(200).required()
  }).unknown(false)).default([])
}).unknown(false);

export function validateMetadata(req, res, next) {
  if (Object.keys(req.body || {}).some(key => key !== 'metadata')) return res.status(400).json({ error: 'Unexpected form field' });
  let input;
  try { input = req.body?.metadata === undefined ? {} : JSON.parse(req.body.metadata); }
  catch { return res.status(400).json({ error: 'metadata must be valid JSON' }); }
  const { value, error } = metadataSchema.validate(input, { convert: false, abortEarly: false });
  if (error) return res.status(400).json({ error: 'Invalid metadata' });
  req.metadata = value;
  next();
}
