# Déploiement VulnScope sur Vercel

## Structure du projet

Le projet VulnScope est composé de deux parties :
- **Frontend** (Next.js) : Peut être déployé sur Vercel
- **Backend** (FastAPI) : Doit être déployé sur un serveur (Render, Railway, GCP, etc.)

## Téléchargement des rapports en production

### Architecture du téléchargement

```
[Utilisateur] → [Frontend Vercel] → [API Route /api/reports/{id}/download] → [Backend FastAPI] → [Fichier téléchargé]
```

### Routes API implémentées

1. **Frontend (Next.js API Routes)**
   - `GET /api/reports` - Liste des rapports
   - `POST /api/reports/generate` - Générer un rapport
   - `GET /api/reports/{id}/download` - Télécharger un rapport

2. **Backend (FastAPI)**
   - `GET /api/v1/reports` - Liste des rapports
   - `POST /api/v1/reports/generate` - Générer un rapport
   - `GET /api/v1/reports/{id}/download` - Télécharger un rapport

### Configuration Vercel

#### Variables d'environnement requises

Dans le dashboard Vercel, configurez les variables suivantes :

```
API_URL=https://votre-backend.onrender.com
NEXT_PUBLIC_API_URL=https://votre-backend.onrender.com/api/v1
NEXTAUTH_URL=https://votre-frontend.vercel.app
NEXTAUTH_SECRET=<généré automatiquement>
```

#### Fichier vercel.json

Le fichier `frontend/vercel.json` configure :
- Les fonctions serverless avec un timeout de 60 secondes
- Les headers CORS pour les routes de rapports
- Le build Next.js

### Formats de rapport supportés

| Format | Description | Content-Type |
|--------|-------------|--------------|
| JSON | Format JSON structuré | application/json |
| HTML | Rapport web visualisable | text/html |
| CSV | Tableur | text/csv |
| SARIF | Format d'analyse statique | application/json |
| PDF | HTML convertible en PDF | text/html |

### Comment utiliser le téléchargement

#### Via l'interface web

1. Allez sur la page "Reports"
2. Sélectionnez un scan terminé
3. Choisissez le format souhaité
4. Cliquez sur "Generate Report"
5. Cliquez sur "Download" dans l'historique des rapports

#### Via l'API directement

```bash
# Générer un rapport
curl -X POST https://votre-frontend.vercel.app/api/reports/generate \
  -H "Content-Type: application/json" \
  -d '{"scan_id": "uuid-du-scan", "name": "Mon Rapport", "format": "html"}'

# Télécharger un rapport
curl -O -J https://votre-frontend.vercel.app/api/reports/{report-id}/download
```

### Dépannage

#### Erreur "Impossible de se connecter au serveur backend"

Vérifiez que :
1. Le backend est bien déployé et accessible
2. La variable `API_URL` est correctement configurée
3. Le backend autorise les requêtes depuis le domaine Vercel (CORS)

#### Timeout lors du téléchargement

Les rapports volumineux peuvent nécessiter plus de temps. Le timeout est configuré à 60 secondes dans `vercel.json`.

### Commandes utiles

```bash
# Déploiement local pour test
cd frontend
npm run build
npm run start

# Déploiement sur Vercel
vercel --prod

# Vérifier les logs
vercel logs
```

## Checklist de déploiement

- [ ] Backend déployé et accessible
- [ ] Variables d'environnement configurées dans Vercel
- [ ] Frontend déployé sur Vercel
- [ ] Test de génération de rapport
- [ ] Test de téléchargement de rapport
- [ ] Vérification des logs