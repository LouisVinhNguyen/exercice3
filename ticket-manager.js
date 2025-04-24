const express = require('express');
const { body, validationResult, param, query } = require('express-validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('./knex');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'secret_key';

app.use(express.json());

// Middleware d'authentification
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Token d\'authentification manquant' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Récupérer l'utilisateur depuis la base de données
    const user = await db('users').where({ id: decoded.id }).first();
    
    if (!user) {
      return res.status(403).json({ message: 'Utilisateur non trouvé' });
    }
    
    req.user = user;
    next();
  } catch (error) {
    return res.status(403).json({ message: 'Token invalide ou expiré', error: error.message });
  }
};

// Middleware pour vérifier le rôle d'administrateur
const isAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Accès non autorisé. Seul un administrateur peut effectuer cette action.' });
  }
  next();
};

// Middleware pour vérifier que l'utilisateur n'est pas un administrateur
const isNotAdmin = (req, res, next) => {
  if (req.user.role === 'admin') {
    return res.status(403).json({ message: 'Les administrateurs ne peuvent pas accéder à cette ressource.' });
  }
  next();
};

// Middleware pour vérifier le rôle de technicien
const isTechnician = (req, res, next) => {
  if (req.user.role !== 'technician') {
    return res.status(403).json({ message: 'Accès non autorisé. Seul un technicien peut effectuer cette action.' });
  }
  next();
};

/**
 * Route pour réinitialiser la base de données (pour le développement)
 */
app.delete('/reset', async (req, res) => {
  try {
    await db('tickets').del();
    await db('users').where('role', '!=', 'admin').del();
    res.status(200).json({ message: 'Base de données réinitialisée avec succès.' });
  } catch (error) {
    res.status(500).json({ message: 'Erreur lors de la réinitialisation de la base de données.', error: error.message });
  }
});

/**
 * Route spéciale pour créer un compte administrateur (utilisation en développement uniquement)
 * Cette route ne devrait pas être exposée en production
 */
app.post('/api/setup/admin', [
  body('username').notEmpty().withMessage('Le nom d\'utilisateur est requis'),
  body('password').isLength({ min: 6 }).withMessage('Le mot de passe doit contenir au moins 6 caractères'),
  body('email').isEmail().withMessage('Email invalide')
], async (req, res) => {
  // Validation des entrées
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { username, password, email } = req.body;

  try {
    // Vérifier si un admin existe déjà avec ce nom d'utilisateur ou email
    const existingAdmin = await db('users').where({ username }).orWhere({ email }).first();
    if (existingAdmin) {
      return res.status(409).json({ message: 'Un utilisateur avec ce nom ou cet email existe déjà' });
    }

    // Hasher le mot de passe
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Insérer le nouvel administrateur
    const [adminId] = await db('users').insert({
      username,
      password: hashedPassword,
      email,
      role: 'admin'
    });

    res.status(201).json({ message: 'Compte administrateur créé avec succès', adminId });
  } catch (error) {
    res.status(500).json({ message: 'Erreur lors de la création du compte administrateur', error: error.message });
  }
});

/**
 * POST /api/auth/admin
 * Connexion d'un administrateur
 */
app.post('/api/auth/admin', [
  body('username').notEmpty().withMessage('Le nom d\'utilisateur est requis'),
  body('password').notEmpty().withMessage('Le mot de passe est requis')
], async (req, res) => {
  // Validation des entrées
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { username, password } = req.body;

  try {
    const admin = await db('users')
      .where({ username, role: 'admin' })
      .first();

    if (!admin) {
      return res.status(401).json({ message: 'Nom d\'utilisateur ou mot de passe incorrect' });
    }

    // Dans une application réelle, utilisez bcrypt.compare pour vérifier le mot de passe
    const validPassword = await bcrypt.compare(password, admin.password);
    if (!validPassword) {
      return res.status(401).json({ message: 'Nom d\'utilisateur ou mot de passe incorrect' });
    }

    const token = jwt.sign({ id: admin.id, role: admin.role }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, userId: admin.id, role: admin.role });
  } catch (error) {
    res.status(500).json({ message: 'Erreur lors de la connexion', error: error.message });
  }
});

/**
 * POST /api/auth/new
 * Inscription d'un nouvel utilisateur ou technicien (nécessite des droits d'administrateur)
 */
app.post('/api/auth/new', authenticateToken, isAdmin, [
  body('username').notEmpty().withMessage('Le nom d\'utilisateur est requis'),
  body('password').isLength({ min: 6 }).withMessage('Le mot de passe doit contenir au moins 6 caractères'),
  body('email').isEmail().withMessage('Email invalide'),
  body('role').isIn(['user', 'technician']).withMessage('Le rôle doit être "user" ou "technician"')
], async (req, res) => {
  // Validation des entrées
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { username, password, email, role } = req.body;

  try {
    // Vérifier si l'utilisateur existe déjà
    const existingUser = await db('users').where({ username }).orWhere({ email }).first();
    if (existingUser) {
      return res.status(409).json({ message: 'Le nom d\'utilisateur ou l\'email existe déjà' });
    }

    // Hasher le mot de passe
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Insérer le nouvel utilisateur
    const [userId] = await db('users').insert({
      username,
      password: hashedPassword,
      email,
      role
    });

    res.status(201).json({ message: `${role === 'user' ? 'Utilisateur' : 'Technicien'} créé avec succès`, userId });
  } catch (error) {
    res.status(500).json({ message: 'Erreur lors de la création de l\'utilisateur', error: error.message });
  }
});

/**
 * POST /api/auth/login
 * Authentification d'un utilisateur ou technicien
 */
app.post('/api/auth/login', [
  body('username').notEmpty().withMessage('Le nom d\'utilisateur est requis'),
  body('password').notEmpty().withMessage('Le mot de passe est requis')
], async (req, res) => {
  // Validation des entrées
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { username, password } = req.body;

  try {
    // Récupérer l'utilisateur (non-admin uniquement)
    const user = await db('users')
      .where({ username })
      .whereNot({ role: 'admin' })
      .first();

    if (!user) {
      return res.status(401).json({ message: 'Nom d\'utilisateur ou mot de passe incorrect' });
    }

    // Vérifier le mot de passe
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ message: 'Nom d\'utilisateur ou mot de passe incorrect' });
    }

    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, userId: user.id, role: user.role });
  } catch (error) {
    res.status(500).json({ message: 'Erreur lors de la connexion', error: error.message });
  }
});

/**
 * POST /api/tickets
 * Créer un nouveau ticket (utilisateur ou technicien uniquement)
 */
app.post('/api/tickets', authenticateToken, isNotAdmin, [
  body('title').notEmpty().withMessage('Le titre est requis'),
  body('description').notEmpty().withMessage('La description est requise'),
  body('status').isIn(['open', 'in progress', 'closed']).withMessage('Le statut doit être "open", "in progress" ou "closed"'),
  body('technicianId').optional({ nullable: true }).isInt().withMessage('L\'ID du technicien doit être un entier valide')
], async (req, res) => {
  // Validation des entrées
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { title, description, status, technicianId } = req.body;
  const userId = req.user.id;

  try {
    // Vérifier que le technicien existe si un ID est fourni
    if (technicianId !== null && technicianId !== undefined) {
      const technicianExists = await db('users')
        .where({ id: technicianId, role: 'technician' })
        .first();
      
      if (!technicianExists) {
        return res.status(404).json({ message: 'Technicien non trouvé' });
      }
    }

    // Préparer les données du ticket
    const ticketData = {
      title,
      description,
      status,
      user_id: userId,
      technician_id: technicianId || null,
      created_at: new Date().toISOString()
    };

    // Si le statut est "closed", ajouter la date de fermeture
    if (status === 'closed') {
      ticketData.closed_at = new Date().toISOString();
    }

    // Insérer le ticket
    const [ticketId] = await db('tickets').insert(ticketData);
    
    res.status(201).json({
      message: 'Ticket créé avec succès',
      ticketId,
      ticket: { id: ticketId, ...ticketData }
    });
  } catch (error) {
    res.status(500).json({ message: 'Erreur lors de la création du ticket', error: error.message });
  }
});

/**
 * GET /api/tickets
 * Obtenir la liste des tickets (filtré par utilisateur si non technicien)
 */
app.get('/api/tickets', authenticateToken, isNotAdmin, async (req, res) => {
  try {
    let tickets;
    
    // Les techniciens peuvent voir tous les tickets
    if (req.user.role === 'technician') {
      tickets = await db('tickets')
        .select('tickets.*', 'users.username as creator_username')
        .leftJoin('users', 'tickets.user_id', 'users.id')
        .orderBy('tickets.created_at', 'desc');
    } else {
      // Les utilisateurs normaux ne voient que leurs propres tickets
      tickets = await db('tickets')
        .where('user_id', req.user.id)
        .orderBy('created_at', 'desc');
    }
    
    res.status(200).json(tickets);
  } catch (error) {
    res.status(500).json({ message: 'Erreur lors de la récupération des tickets', error: error.message });
  }
});

/**
 * GET /api/tickets/:id
 * Obtenir les détails d'un ticket spécifique
 */
app.get('/api/tickets/:id', authenticateToken, isNotAdmin, [
  param('id').isInt().withMessage('L\'ID du ticket doit être un entier valide')
], async (req, res) => {
  // Validation des entrées
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { id } = req.params;

  try {
    const ticket = await db('tickets')
      .select('tickets.*', 'u1.username as creator_username', 'u2.username as technician_username')
      .leftJoin('users as u1', 'tickets.user_id', 'u1.id')
      .leftJoin('users as u2', 'tickets.technician_id', 'u2.id')
      .where('tickets.id', id)
      .first();

    if (!ticket) {
      return res.status(404).json({ message: 'Ticket non trouvé' });
    }

    // Vérifier que l'utilisateur a le droit de voir ce ticket
    if (req.user.role !== 'technician' && ticket.user_id !== req.user.id) {
      return res.status(403).json({ message: 'Vous n\'êtes pas autorisé à voir ce ticket' });
    }

    res.status(200).json(ticket);
  } catch (error) {
    res.status(500).json({ message: 'Erreur lors de la récupération du ticket', error: error.message });
  }
});

/**
 * PUT /api/tickets/:id
 * Mettre à jour un ticket (technicien uniquement)
 */
app.put('/api/tickets/:id', authenticateToken, isNotAdmin, [
  param('id').isInt().withMessage('L\'ID du ticket doit être un entier valide'),
  body('title').notEmpty().withMessage('Le titre est requis'),
  body('description').notEmpty().withMessage('La description est requise'),
  body('status').isIn(['open', 'in progress', 'closed']).withMessage('Le statut doit être "open", "in progress" ou "closed"'),
  body('technicianId').optional({ nullable: true }).isInt().withMessage('L\'ID du technicien doit être un entier valide')
], async (req, res) => {
  // Validation des entrées
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { id } = req.params;
  const { title, description, status, technicianId } = req.body;

  try {
    // Vérifier que le ticket existe
    const ticket = await db('tickets').where({ id }).first();
    if (!ticket) {
      return res.status(404).json({ message: 'Ticket non trouvé' });
    }

    // Seul un technicien peut mettre à jour un ticket
    if (req.user.role !== 'technician') {
      return res.status(403).json({ message: 'Seul un technicien peut mettre à jour un ticket' });
    }

    // Vérifier que le technicien existe si un ID est fourni
    if (technicianId !== null && technicianId !== undefined) {
      const technicianExists = await db('users')
        .where({ id: technicianId, role: 'technician' })
        .first();
      
      if (!technicianExists) {
        return res.status(404).json({ message: 'Technicien non trouvé' });
      }
    }

    // Préparer les données de mise à jour
    const updateData = {
      title,
      description,
      status,
      technician_id: technicianId || null,
    };

    // Si le statut change à "closed", ajouter la date de fermeture
    if (status === 'closed' && ticket.status !== 'closed') {
      updateData.closed_at = new Date().toISOString();
    }
    
    // Si le ticket passe de "closed" à un autre statut, supprimer la date de fermeture
    if (status !== 'closed' && ticket.status === 'closed') {
      updateData.closed_at = null;
    }

    // Mettre à jour le ticket
    await db('tickets').where({ id }).update(updateData);
    
    // Récupérer le ticket mis à jour
    const updatedTicket = await db('tickets').where({ id }).first();
    
    res.status(200).json({
      message: 'Ticket mis à jour avec succès',
      ticket: updatedTicket
    });
  } catch (error) {
    res.status(500).json({ message: 'Erreur lors de la mise à jour du ticket', error: error.message });
  }
});

/**
 * DELETE /api/admin/tickets/:id
 * Supprimer un ticket (administrateur uniquement)
 */
app.delete('/api/admin/tickets/:id', authenticateToken, isAdmin, [
  param('id').isInt().withMessage('L\'ID du ticket doit être un entier valide')
], async (req, res) => {
  // Validation des entrées
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { id } = req.params;

  try {
    // Vérifier que le ticket existe
    const ticket = await db('tickets').where({ id }).first();
    if (!ticket) {
      return res.status(404).json({ message: 'Ticket non trouvé' });
    }

    // Supprimer le ticket
    await db('tickets').where({ id }).del();
    
    res.status(200).json({ message: 'Ticket supprimé avec succès' });
  } catch (error) {
    res.status(500).json({ message: 'Erreur lors de la suppression du ticket', error: error.message });
  }
});

// Lancer le serveur
app.listen(PORT, () => {
  console.log(`Serveur en cours d'exécution sur http://localhost:${PORT}`);
});