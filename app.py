from flask import Flask , render_template , url_for , redirect , request
from flask_sqlalchemy import SQLAlchemy
from  flask_login import UserMixin , login_user , LoginManager , login_required , logout_user , current_user
from  flask_wtf import FlaskForm
from wtforms import StringField , PasswordField , SubmitField
from wtforms.validators import InputRequired , Length , ValidationError
from flask_bcrypt import Bcrypt 
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_BINDS'] = { 'two' : 'sqlite:///test.db'}
app.config['SECRET_KEY'] = 'thisisasecretkey'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model , UserMixin):
    id = db.Column(db.Integer , primary_key = True)
    username = db.Column(db.String(20) , nullable = False , unique = True)
    password = db.Column(db.String(80) ,nullable = False)


class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4 , max=20)] , render_kw={"placeholder":"Username"})
    password = PasswordField(validators=[InputRequired() , Length(min=4 , max=20)] , render_kw={"placeholder":"password"})

    submit = SubmitField("Register")

    def validate_username(self , username):
        existing_user_username = User.query.filter_by(username = username.data).first()
        if existing_user_username:
            raise ValidationError("User already exists , Please choose Different user name ")


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4 , max=20)] , render_kw={"placeholder":"Username"})
    password = PasswordField(validators=[InputRequired() , Length(min=4 , max=20)] , render_kw={"placeholder":"password"})

    submit = SubmitField("Login")


@app.route("/")
def home():
    return render_template('home.html')

@app.route('/login' ,methods =['GET' ,'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username = form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password , form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html' , form = form)


@app.route('/dashboard', methods =['GET' ,'POST'])
@login_required
def dashboard():
     
    
    return render_template('dashboard.html' , user = current_user.username)

@app.route('/logout' , methods = ['GET' ,'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods =['GET' ,'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username =form.username.data , password = hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html' , form = form)



class Todo(db.Model):
    __bind_key__ = 'two'
    id = db.Column(db.Integer , primary_key = True)
    content = db.Column(db.String(200) , nullable = False)
    ###
    date_created = db.Column(db.DateTime , default = datetime.utcnow)
    user_id = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return '<Task %r>' % self.id 


@app.route('/index', methods = ['POST' , 'GET'])

def index():
    if request.method == 'POST':
        task_content = request.form['content']
        new_task = Todo(content = task_content , user_id = current_user.id)

        try :
            db.session.add(new_task)
            db.session.commit()
            return redirect('/index')
        except:
            return "Unable to add new tas k"


    else:
        tasks = Todo.query.filter_by(user_id = current_user.id).order_by(Todo.date_created).all() 
        return render_template('index.html' , tasks = tasks  , user = current_user.username)

@app.route('/delete/<int:id>')
def delete(id):
    task_to_delete = Todo.query.get_or_404(id)
    try :
        db.session.delete(task_to_delete)
        db.session.commit()
        return redirect('/index')
    except:
        return "Unable to delete the task"



if __name__ == "__main__":
    app.run(debug=True)
