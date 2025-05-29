# ITSutra Resume Tweaker

An AI-powered resume analysis and optimization tool that helps match resumes with job descriptions while maintaining the original structure and experience.

## Features

- Domain-specific resume analysis
- Keyword matching and suggestions
- Experience compatibility checking
- Multiple file format support (.docx, .doc, .txt, .pdf)
- Secure authentication (@itsutra.com domain)
- Analysis history tracking

## Tech Stack

- **Backend**: Flask (Python)
- **Database**: PostgreSQL
- **AI/ML**: Hugging Face Transformers, Sentence Transformers
- **Frontend**: Bootstrap 5, JavaScript
- **Authentication**: Flask-Login

## Local Development Setup

1. Clone the repository:
```bash
git clone https://github.com/salinbajracharya/Resumetweaker.git
cd Resumetweaker
```

2. Create and activate virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

5. Initialize database:
```bash
python create_db.py
```

6. Run the application:
```bash
flask run
```

The application will be available at `http://127.0.0.1:5000`

## Environment Variables

Create a `.env` file with the following variables:
```
FLASK_APP=app.py
FLASK_ENV=development
SECRET_KEY=your-secret-key
DATABASE_URL=postgresql://user:password@localhost/dbname
```

## Deployment

The application is configured for deployment on Render or similar platforms. Required files:
- `Procfile` - For Gunicorn web server
- `requirements.txt` - Python dependencies
- `runtime.txt` - Python version specification

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- ITSutra Inc. for the project requirements and branding
- Hugging Face for open-source AI models
- Flask and Python communities for excellent documentation 