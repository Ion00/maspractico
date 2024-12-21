from app import create_app

app = create_app('config.TestingConfig')

if __name__ == "__main__":
    app.run(debug=True)
