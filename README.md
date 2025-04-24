# Système de Gestion de Tickets

## Description

Ce projet est une API REST pour gérer un système de tickets de support technique. L'application permet la création, la consultation et la mise à jour de tickets par différents types d'utilisateurs ayant des rôles et des permissions spécifiques.

## Points Importants

### Authentification et Sécurité
- **JWT (JSON Web Token)** : Toutes les routes sont sécurisées avec JWT pour l'authentification.
- **Hachage de mots de passe** : Les mots de passe sont hachés avec bcrypt avant d'être stockés dans la base de données.
- **Validation des données** : Toutes les entrées sont validées à l'aide d'express-validator.

### Types d'Utilisateurs
- **Utilisateur standard** : Peut créer des tickets et consulter ses propres tickets.
- **Technicien** : Peut voir tous les tickets, créer des tickets et les mettre à jour.
- **Administrateur** : Peut créer des utilisateurs et techniciens, et supprimer des tickets. Ne peut pas créer ou mettre à jour des tickets.

### Routes API

#### Authentification
- **POST /api/setup/admin** : Création d'un compte administrateur (pour initialisation/tests uniquement).
- **POST /api/auth/admin** : Connexion pour les administrateurs.
- **POST /api/auth/new** : Création d'un nouvel utilisateur ou technicien (admin uniquement).
- **POST /api/auth/login** : Connexion pour les utilisateurs et techniciens.

#### Gestion des Tickets
- **POST /api/tickets** : Création d'un nouveau ticket (utilisateurs et techniciens uniquement).
- **GET /api/tickets** : Récupération de la liste des tickets (filtrée selon le rôle).
- **GET /api/tickets/:id** : Consultation des détails d'un ticket.
- **PUT /api/tickets/:id** : Mise à jour d'un ticket (techniciens uniquement).
- **DELETE /api/admin/tickets/:id** : Suppression d'un ticket (administrateurs uniquement).

#### Développement
- **DELETE /reset** : Réinitialisation de la base de données (développement uniquement).

## Structure de la Base de Données

### Table `users`
- `id` : Identifiant unique
- `username` : Nom d'utilisateur (unique)
- `password` : Mot de passe haché
- `email` : Adresse email (unique)
- `role` : Rôle de l'utilisateur (admin, technicien, user)
- `created_at` : Date de création
- `updated_at` : Date de mise à jour

### Table `tickets`
- `id` : Identifiant unique
- `title` : Titre du ticket
- `description` : Description du problème
- `status` : Statut du ticket (open, in progress, closed)
- `user_id` : ID de l'utilisateur qui a créé le ticket
- `technician_id` : ID du technicien assigné (optionnel)
- `created_at` : Date de création
- `closed_at` : Date de fermeture (optionnelle)

## Installation

Pour installer les dépendances du projet, exécutez la commande suivante :

```bash
npm install
```

Les dépendances principales incluent :
- express
- knex
- sqlite3
- jsonwebtoken
- bcryptjs
- express-validator

## Démarrage

Pour lancer le serveur, exécutez :

```bash
node ticket-manager.js
```

Le serveur sera accessible à l'adresse `http://localhost:3000`.

## Tests

Le fichier `requests.http` contient des exemples de requêtes pour tester l'API. Vous pouvez les exécuter avec l'extension REST Client de VS Code ou adapter les requêtes pour Postman.

Pour tester l'application, suivez ces étapes :
1. Réinitialisez la base de données
2. Créez un compte administrateur
3. Connectez-vous en tant qu'administrateur
4. Créez des utilisateurs et techniciens
5. Testez les différentes fonctionnalités selon les rôles

## Auteur

LouisVinhNguyen