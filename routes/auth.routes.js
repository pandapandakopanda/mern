const {Router} = require('express')
const {check, validationResult} = require('express-validator')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
const router = Router()
const User = require('../models/User')
const config = require('config')

router.post(
  '/register',
  [
    check('email', 'Invalid email').isEmail(),
    check('password','min length 6 chars').isLength({min:6})
  ],
  async (req,res)=>{
  try{
    const errors = validationResult(req)

    if(!errors.isEmpty()) {
      return res.status(400).json({
        message:'Invalid data', 
        errors: errors.array
      })
    }

    const { email, password } = req.body

    const candidate = User.findOne({email})

    if(candidate ) {
      return res.status(400).json({message: 'user has been created already'})
    }
    const hashedPassword = await bcrypt.hash(password, 12)
    const user = new User({email, hashedPassword})

    await user.save()

    res.status(201).json({message:'user has been created'})

  }catch (e) {
    res.status(500).json({message: 'somthing went wrong, try again'})
  }
})

router.post(
  '/login', 
  [
    check('email', 'Please enter correct e-mail').normalizeEmail().isEmail(),
    check('password', 'Enter password').exists()
  ],
  async (req,res)=>{
  try
  {
    const errors = validationResult( req )

    if ( !errors.isEmpty() )
    {
      return res.status( 400 ).json( {
        message: 'Invalid data',
        errors: errors.array
      } )
    }

    const {email, password} = req.body

    const user = await User.findOne({email})
    if(!user){
      return res.status(400).json({message: 'didnt find user'})
    }

    const isMatch = await bcrypt.compare(password, user.password)

    const token = jwt.sign(
      {userId: user.id},
      config.get('jwtSecret'),
      {expiresIn:'1h'}
    )


    res.json({token, userId: user.id})

    if(!isMatch) {
      return res.status(400).json({message: 'invalid Password'})
    }



  } catch ( e )
  {
    res.status( 500 ).json( {message: 'somthing went wrong, try again'} )
  }
})

module.exports = router