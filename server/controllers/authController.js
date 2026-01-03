import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import userModel from '../models/userModel.js';

export const register = async (req, res) => {
    const { name, email, password } = req.body; //get user data from request body
    //validation for empty fields
    if (!name || !email || !password) {
        return res.json({ success: false, message: 'All fields are required' });
    }

    try {
        const existingUser = await userModel.findOne({ email }); //check if user already exists
        if (existingUser) {
            return res.json({ success: false, message: 'User already exists' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);//password hashing with salt 10

        // create new user
        const user = new userModel({ name, email, password: hashedPassword });//user information
        await user.save();
        
        const token = jwt.sign({ id: user._id }, process.env.Jwt_SECRET, { expiresIn: '1d' });// create token valid for 1 day
        
        res.cookie('token', token, {
            httpOnly: true, //its will be only run on the server side
            secure: process.env.NODE_ENV === 'production', // only send cookie on https
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict', // when ever we run on production environment
            maxAge: 24 * 60 * 60 * 1000, // 1 day
        })
        res.json({ success: true, message: 'User registered successfully' });
    } catch (error) {
        res.json({ success: false, message: error.message });
    }
}

export const login = async (req, res) => {
    const { email, password } = req.body; //get user data from request body
    //validation for empty fields
    if (!email || !password) {
        res.json({ success: false, message: 'All fields are required' });
    }

    try {
        const user = await userModel.findOne({ email });

        if (!user) {
            return res.json({ success: false, message: 'User does not exist' });
        }

        const isMatch = await bcrypt.compare(password, user.password); //compare password
        if (!isMatch) {
            return res.json({ success: false, message: 'Invalid credentials' });
        }

        const token = jwt.sign({ id: user._id }, process.env.Jwt_SECRET, { expiresIn: '1d' });// create token valid for 1 day

        res.cookie('token', token, {
            httpOnly: true, //its will be only run on the server side
            secure: process.env.NODE_ENV === 'production', // only send cookie on https
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict', // when ever we run on production environment
            maxAge: 24 * 60 * 60 * 1000, // 1 day
        })

        return res.json({ success: true, message: 'Login successful' });
    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
}

export const logout = async (req, res) => {
    try {
        res.clearCookie('token', {
            httpOnly: true, //its will be only run on the server side
            secure: process.env.NODE_ENV === 'production', // only send cookie on https
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict', 
        });

        return res.json({ success: true, message: 'Logout successful' });
    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
}
