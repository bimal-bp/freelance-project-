import streamlit as st
import re
import hashlib
import psycopg2
from psycopg2 import sql
from blockchain_interface import BlockchainInterface
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from web3 import Web3

# Connect to PostgreSQL database
def get_db_connection():
    conn = psycopg2.connect(
        "postgresql://freelance%20project_owner:npg_plxMo5JSUr4y@ep-red-river-a5dg5di1-pooler.us-east-2.aws.neon.tech/freelance%20project?sslmode=require"
    )
    return conn

# Initialize database tables
def init_db():
    conn = get_db_connection()
    cur = conn.cursor()

    # Create users table
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            user_type TEXT NOT NULL,
            wallet_address TEXT,
            private_key TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Create freelancer_profiles table
    cur.execute('''
        CREATE TABLE IF NOT EXISTS freelancer_profiles (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            skills TEXT NOT NULL,
            experience INTEGER,
            hourly_rate REAL,
            bio TEXT
        )
    ''')

    # Create projects table
    cur.execute('''
        CREATE TABLE IF NOT EXISTS projects (
            id SERIAL PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            employer_id INTEGER REFERENCES users(id),
            freelancer_id INTEGER REFERENCES users(id),
            status TEXT DEFAULT 'open',
            budget REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            contract_address TEXT
        )
    ''')

    conn.commit()
    cur.close()
    conn.close()

# Initialize database
init_db()

# Connect to local Ganache instance
w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:8545'))

if not w3.is_connected():
    raise Exception("Failed to connect to Ganache!")

# Initialize BlockchainInterface
blockchain = BlockchainInterface(provider_url="HTTP://127.0.0.1:8545")  # Use Ganache or a testnet

# Helper functions
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def is_valid_username(username):
    return bool(re.match("^[a-zA-Z0-9_]*$", username))

def is_valid_email(email):
    email_regex = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
    return bool(re.match(email_regex, email))

def is_valid_password(password):
    password_regex = r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%?&])[A-Za-z\d@$!%?&]{8,}$"
    return bool(re.match(password_regex, password))

def create_user(username, password, email, user_type):
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        hashed_password = hash_password(password)
        wallet_info = blockchain.create_wallet()
        cur.execute('''
            INSERT INTO users (username, password, email, user_type, wallet_address, private_key)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id
        ''', (username, hashed_password, email, user_type, wallet_info['address'], wallet_info['private_key']))
        user_id = cur.fetchone()[0]
        conn.commit()
        return user_id
    except psycopg2.IntegrityError:
        return None
    finally:
        cur.close()
        conn.close()

def verify_user(email, password):
    conn = get_db_connection()
    cur = conn.cursor()
    hashed_password = hash_password(password)
    cur.execute('SELECT * FROM users WHERE email = %s AND password = %s', (email, hashed_password))
    user = cur.fetchone()
    cur.close()
    conn.close()
    return user

def create_freelancer_profile(user_id, skills, experience, hourly_rate, bio):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('''
        INSERT INTO freelancer_profiles (user_id, skills, experience, hourly_rate, bio)
        VALUES (%s, %s, %s, %s, %s)
    ''', (user_id, skills, experience, hourly_rate, bio))
    conn.commit()
    cur.close()
    conn.close()

def get_freelancer_profile(user_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM freelancer_profiles WHERE user_id = %s', (user_id,))
    profile = cur.fetchone()
    cur.close()
    conn.close()
    return profile

def create_project(title, description, employer_id, budget):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('''
        INSERT INTO projects (title, description, employer_id, budget)
        VALUES (%s, %s, %s, %s)
        RETURNING id
    ''', (title, description, employer_id, budget))
    project_id = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()
    return project_id

def get_projects(employer_id=None, freelancer_id=None, status='open'):
    conn = get_db_connection()
    cur = conn.cursor()
    
    query = "SELECT * FROM projects WHERE status = %s"
    params = [status]

    if employer_id:
        query += " AND employer_id = %s"
        params.append(employer_id)
    elif freelancer_id:
        query += " AND freelancer_id = %s"
        params.append(freelancer_id)
    
    cur.execute(query, params)
    projects = cur.fetchall()
    cur.close()
    conn.close()
    return projects

def get_all_freelancers():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('''
        SELECT users.id, users.username, users.email, freelancer_profiles.skills, 
               freelancer_profiles.experience, freelancer_profiles.hourly_rate, 
               freelancer_profiles.bio, users.wallet_address
        FROM users 
        JOIN freelancer_profiles ON users.id = freelancer_profiles.user_id
        WHERE users.user_type = 'freelancer'
    ''')
    freelancers = cur.fetchall()
    cur.close()
    conn.close()
    return freelancers

def match_freelancers(project_description, required_skills):
    freelancers = get_all_freelancers()
    if not freelancers:
        return []

    project_text = f"{project_description} {required_skills}"
    texts = [project_text]
    freelancer_data = []

    for freelancer in freelancers:
        freelancer_text = f"{freelancer[3] or ''} {freelancer[4] or ''} {freelancer[6] or ''}"
        texts.append(freelancer_text)
        freelancer_data.append({
            'id': freelancer[0],
            'username': freelancer[1],
            'email': freelancer[2],
            'skills': freelancer[3],
            'experience': freelancer[4],
            'hourly_rate': freelancer[5],
            'bio': freelancer[6],
            'wallet_address': freelancer[7]
        })

    vectorizer = TfidfVectorizer(stop_words='english')
    tfidf_matrix = vectorizer.fit_transform(texts)
    cosine_similarities = cosine_similarity(tfidf_matrix[0:1], tfidf_matrix[1:])

    for idx, score in enumerate(cosine_similarities[0]):
        freelancer_data[idx]['match_score'] = score
    matched_freelancers = [freelancer for freelancer in freelancer_data if freelancer['match_score'] > 0]

    matched_freelancers = sorted(matched_freelancers, key=lambda x: x['match_score'], reverse=True)
    return matched_freelancers

# Streamlit UI
if 'user' not in st.session_state:
    st.session_state.user = None
if 'page' not in st.session_state:
    st.session_state.page = 'home'

def sidebar_navigation():
    if st.session_state.user:
        st.sidebar.title("Navigation")
        user_type = st.session_state.user[4]
        
        if user_type == 'employer':
            options = ["Post Project", "My Projects", "Find Freelancers", "Wallet"]
        else:
            options = ["My Profile", "Available Projects", "My Projects", "Wallet"]
        
        choice = st.sidebar.selectbox("Menu", options)
        
        if st.sidebar.button("Logout"):
            st.session_state.user = None
            st.session_state.page = 'home'
            st.rerun()
        
        return choice

def home_page():
    st.title("Welcome to SmartLancer!")
    
    col1, col2, col3 = st.columns([1, 1, 1])
    
    with col1:
        st.image("freelancer-img.png", use_container_width=True)

    with col2:
        st.header("New User?")
        user_type = st.selectbox("Select User Type", ["Employer", "Freelancer"])
        if st.button("Register", key="register"):
            st.session_state.page = 'register'
            st.session_state.registration_type = user_type.lower()
            st.rerun()

    with col3:
        st.header("Existing User?")
        if st.button("Login", key="login"):
            st.session_state.page = 'login'
            st.rerun()

def register_page():
    st.title("Registration")
    user_type = st.session_state.registration_type

    with st.form(f"{user_type}_registration"):
        st.subheader(f"{user_type.capitalize()} Registration")

        username = st.text_input("Username")
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        confirm_password = st.text_input("Confirm Password", type="password")

        if user_type == 'freelancer':
            skills = st.text_input("Skills (comma-separated)")
            experience = st.number_input("Years of Experience", min_value=0)
            hourly_rate = st.number_input("Hourly Rate ($)", min_value=0)
            bio = st.text_area("Bio")

        if st.form_submit_button("Register"):
            if not username or not is_valid_username(username):
                st.error("Invalid username!")
                return
            if not is_valid_email(email):
                st.error("Invalid email!")
                return
            if not is_valid_password(password):
                st.error("Invalid password!")
                return
            if password != confirm_password:
                st.error("Passwords don't match!")
                return

            user_id = create_user(username, password, email, user_type)

            if user_id:
                if user_type == 'freelancer':
                    create_freelancer_profile(user_id, skills, experience, hourly_rate, bio)
                st.success("Registration successful! Please login.")
                st.session_state.page = 'login'
                st.rerun()
            else:
                st.error("Username or email already exists!")

def login_page():
    st.title("Login")

    with st.form("login_form"):
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")

        if st.form_submit_button("Login"):
            if not email or not password:
                st.error("Both email and password are required!")
            else:
                user = verify_user(email, password)
                if user:
                    st.session_state.user = user
                    st.session_state.page = 'dashboard'
                    st.rerun()
                else:
                    st.error("Invalid credentials!")

def post_project():
    st.subheader("Post New Project")

    with st.form("project_form"):
        title = st.text_input("Project Title")
        description = st.text_area("Project Description")
        budget = st.number_input("Budget ($)", min_value=0.0)

        if st.form_submit_button("Post Project"):
            if not title or not description or budget <= 0.0:
                st.error("Please fill in all fields and set a valid budget greater than 0.")
            else:
                project_id = create_project(title, description, st.session_state.user[0], budget)
                if project_id:
                    st.success("Project posted successfully!")
                else:
                    st.error("Failed to post the project. Please try again.")

def view_projects(employer_id=None, freelancer_id=None, available=False):
    conn = get_db_connection()
    cur = conn.cursor()

    if employer_id:
        cur.execute('SELECT * FROM projects WHERE employer_id = %s', (employer_id,))
    elif freelancer_id and not available:
        cur.execute('SELECT * FROM projects WHERE status = %s AND freelancer_id = %s', ('assigned', freelancer_id))
    elif available:
        cur.execute('SELECT * FROM projects WHERE status = %s AND freelancer_id IS NULL', ('open',))
    else:
        cur.execute('SELECT * FROM projects WHERE status = %s', ('open',))

    projects = cur.fetchall()
    cur.close()
    conn.close()

    if not projects:
        st.write("No projects found.")
        return

    for project in projects:
        with st.expander(f"Project: {project[1]}"):
            st.write(f"Description: {project[2]}")
            st.write(f"Budget: ${project[6]}")
            st.write(f"Status: {project[5]}")

            if st.session_state.user[4] == 'freelancer' and project[5] == 'open':
                if st.button("Apply", key=f"apply_{project[0]}"):
                    conn = get_db_connection()
                    cur = conn.cursor()
                    cur.execute('UPDATE projects SET freelancer_id = %s, status = %s WHERE id = %s',
                    (st.session_state.user[0], 'assigned', project[0]))
                    conn.commit()
                    cur.close()
                    conn.close()
                    st.success("Applied successfully!")
                    st.rerun()

def find_freelancers_page():
    st.subheader("Find Freelancers")

    if 'search_params' not in st.session_state:
        st.session_state.search_params = {
            'project_id': None,
            'description': '',
            'skills': ''
        }

    projects = get_projects(employer_id=st.session_state.user[0], status='open')
    if not projects:
        st.warning("You have no open projects. Please post a project first.")
        return

    project_options = {p[0]: p[1] for p in projects}
    selected_project_id = st.selectbox(
        "Select a Project to Hire For",
        options=list(project_options.keys()),
        format_func=lambda x: project_options[x],
        key='project_select'
    )

    if st.session_state.search_params['project_id'] != selected_project_id:
        st.session_state.search_params = {
            'project_id': selected_project_id,
            'description': next(p[2] for p in projects if p[0] == selected_project_id),
            'skills': ''
        }

    project_description = st.text_area(
        "Project Description",
        value=st.session_state.search_params['description'],
        key='project_desc'
    )
    required_skills = st.text_input(
        "Required Skills",
        value=st.session_state.search_params['skills'],
        key='project_skills'
    )

    if st.button("Find Matches"):
        st.session_state.search_params.update({
            'description': project_description,
            'skills': required_skills
        })
        st.session_state.refresh_projects = True

    if st.session_state.refresh_projects:
        show_freelancer_matches(selected_project_id, project_description, required_skills)

def show_freelancer_matches(project_id, description, skills):
    matched_freelancers = match_freelancers(description, skills)
    
    if not matched_freelancers:
        st.info("No freelancers found matching your requirements.")
        return

    st.write("### Matched Freelancers")
    
    for freelancer in matched_freelancers:
        with st.container():
            col1, col2, col3 = st.columns([3, 2, 1])
            with col1:
                st.markdown(f"{freelancer['username']}**  \n"
                            f"Skills: {freelancer['skills']}  \n"
                            f"Experience: {freelancer['experience']} yrs  \n" 
                            f"Rate: ${freelancer['hourly_rate']}/hr")
            
            with col2:
                st.markdown(f"Match Score: {freelancer['match_score']*100:.1f}%  \n"
                            f"Wallet: {freelancer['wallet_address']}")
            
            with col3:
                if st.button(
                    "Hire",
                    key=f"hire_{freelancer['id']}_{project_id}",
                    use_container_width=True
                ):
                    handle_hire_action(project_id, freelancer)

def handle_hire_action(project_id, freelancer):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT * FROM projects WHERE id = %s', (project_id,))
        project = cur.fetchone()
        
        if not project:
            st.error("Project not found!")
            return

        contract_address = blockchain.deploy_contract(
            employer_private_key=st.session_state.user[6],
            freelancer_address=freelancer['wallet_address'],
            job_description=project[2],
            amount=project[6]
        )

        cur.execute('''
            UPDATE projects 
            SET freelancer_id = %s, 
                status = %s, 
                contract_address = %s 
            WHERE id = %s
        ''', (freelancer['id'], 'assigned', contract_address, project_id))
        conn.commit()
        
        st.session_state.refresh_projects = False
        st.success(f"Hired {freelancer['username']}! Contract: {contract_address}")
        st.rerun()
    
    except Exception as e:
        st.error(f"Error: {str(e)}")
    finally:
        cur.close()
        conn.close()

def wallet_page():
    st.subheader("Wallet")

    if not st.session_state.user:
        st.error("You must be logged in to view wallet details.")
        return

    if "show_wallet" not in st.session_state:
        st.session_state.show_wallet = False

    password_input = st.text_input("Enter your password to view wallet details", type="password")

    if st.button("Show Wallet Details"):
        if verify_user(st.session_state.user[2], password_input):
            st.session_state.show_wallet = True
        else:
            st.error("Incorrect password! Access denied.")

    if st.session_state.show_wallet:
        wallet_address = st.session_state.user[5]
        private_key = st.session_state.user[6]
        st.write(f"*Wallet Address:* {wallet_address}")
        st.write(f"*Private Key:* {private_key} (Keep it secure!)")

        try:
            wallet_balance_wei = w3.eth.get_balance(wallet_address)
            wallet_balance_eth = w3.from_wei(wallet_balance_wei, 'ether')
            st.write(f"*Balance:* {wallet_balance_eth:.4f} ETH")
        except Exception as e:
            st.write(f"*Balance:* Error fetching balance: {str(e)}")

def main():
    if st.session_state.page == 'home':
        home_page()
    elif st.session_state.page == 'register':
        register_page()
    elif st.session_state.page == 'login':
        login_page()
    elif st.session_state.page == 'dashboard':
        choice = sidebar_navigation()
        wallet_address = st.session_state.user[5]
        balance_wei = blockchain.w3.eth.get_balance(wallet_address)
        balance_eth = blockchain.w3.from_wei(balance_wei, 'ether')

        if not choice:
            return

        if choice == "Post Project":
            post_project()
        elif choice in ["My Projects", "Available Projects"]:
            if st.session_state.user[4] == 'employer':
                view_projects(employer_id=st.session_state.user[0])
            else:
                if choice == "My Projects":
                    view_projects(freelancer_id=st.session_state.user[0])
                else:
                    view_projects(available=True)

        elif choice == "Find Freelancers":
            find_freelancers_page()
        elif choice == "Wallet":
            wallet_page()
        elif choice == "My Profile":
            st.subheader("My Profile")
            profile = get_freelancer_profile(st.session_state.user[0])
            if profile:
                st.write(f"Skills: {profile[2]}")
                st.write(f"Experience: {profile[3]} years")
                st.write(f"Hourly Rate: ${profile[4]}/hour")
                st.write(f"Bio: {profile[5]}")

if __name__ == "__main__":
    main()
