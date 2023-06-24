const User = require('../models/User');
const argon2 = require('argon2');

exports.inscription = async (req, res) => {
    const { email, password, prenom, nom } = req.body;
    
    // regarde si le username fait partie deja partie de la DB
    let user = await User.findOne({ email });

    if (user) {
        return res.status(400).json({ message: 'Ce nom Utilisateur est deja utilise' });
    }

    // Encryption
    const hashedPassword = await argon2.hash(password);

    // Monte les donnees du nouveau user
    user = new User({
        prenom,
        nom,
        email,
        password: hashedPassword
    });

    await user.save();
    res.status(201).json({ message: 'Inscription reussie', user });
};

exports.signIn = async (req, res) => {
    const { email, password } = req.body;

    // Loader le data par email
    const user = await User.findOne({ email });

    if (!user) {
        return res.status(401).json({ error: 'Cet identifiant est invalide' });
    }

    // Regarder la correspondance du password utilisateur avec lencryption dans la BD
    const isMatch = await argon2.verify(user.password, password);

    if (!isMatch) {
        return res.status(401).json({ error: 'Mot de passe erronne' });
    }

    // Send a success response
    res.status(200).json({ message: 'Bienvenue', user });
};
