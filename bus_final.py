import streamlit as st
import pandas as pd
import hashlib

bus_stops_df = pd.read_excel('bus_stops.xlsx')
bus_routes_df=pd.read_excel('bus_routes.xlsx')

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Function to authenticate user
def authenticate(username, password):
    try:
        users_df = pd.read_excel('login.xlsx')
    except FileNotFoundError:
        return False

    hashed_password = hash_password(password)
    if ((users_df['Username'] == username) & (users_df['Password'] == hashed_password)).any():
        return True
    return False

# Function to sign up user
def signup(username, password):
    hashed_password = hash_password(password)
    
    # Read existing user data, if any
    try:
        users_df = pd.read_excel('login.xlsx')
    except FileNotFoundError:
        users_df = pd.DataFrame({'Username': [], 'Password': []})
    
    # Check if username already exists
    if username in users_df['Username'].values:
        st.error('Username already exists. Please choose a different one.')
        return
    
    # Add new user if username is unique
    new_user = pd.DataFrame({'Username': [username], 'Password': [hashed_password]})
    users_df = pd.concat([users_df, new_user], ignore_index=True)
    users_df.to_excel('login.xlsx', index=False)
    st.success('Account created successfully!')



def main():
    bus_stops_df = pd.read_excel('bus_stops.xlsx')
    bus_routes_df=pd.read_excel('bus_routes.xlsx')
    st.sidebar.title('Bus Routing System')
    session_state = st.session_state
    if 'logged_in' not in session_state:
        session_state.logged_in = False

    if not session_state.logged_in:
        st.title('Login/Register')
        login_username = st.text_input('Username')
        login_password = st.text_input('Password', type='password')
        if st.button('Login'):
            if authenticate(login_username, login_password):
                session_state.logged_in = True
                st.success('Logged in successfully!')
            else:
                st.error('Invalid username or password.')

        st.write('Or')

        signup_username = st.text_input('New Username')
        signup_password = st.text_input('New Password', type='password')
        if st.button('Sign Up'):
            signup(signup_username, signup_password)

    else:
        st.sidebar.title('Select Option')
        option = st.sidebar.selectbox('Select Option', ('View Bus Stops', 'View Bus Routes', 'Search Bus Stop', 'Search Bus Route'))

        if option == 'View Bus Stops':
            st.header('Bus Stops')
            st.dataframe(bus_stops_df)

        elif option == 'View Bus Routes':
            st.header('Available buses')
            # Load bus route data
            bus_routes_df = pd.read_excel('bus_routes.xlsx')
            st.dataframe(bus_routes_df)

        elif option == 'Search Bus Stop':
            st.header('Search Bus Stop')
            # Text input for bus stop name
            bus_stop_name = st.text_input('Enter Bus Stop Name')
            filtered_bus_stops_df = pd.DataFrame()  # Define empty DataFrame
            if bus_stop_name:
                filtered_bus_stops_df = bus_stops_df[bus_stops_df['stop1'].str.contains(bus_stop_name, case=False) |
                                             bus_stops_df['stop2'].str.contains(bus_stop_name, case=False) |
                                             bus_stops_df['stop3'].str.contains(bus_stop_name, case=False) |
                                             bus_stops_df['stop4'].str.contains(bus_stop_name, case=False) |
                                             bus_stops_df['stop5'].str.contains(bus_stop_name, case=False) |
                                             bus_stops_df['stop6'].str.contains(bus_stop_name, case=False) |
                                              bus_stops_df['From'].str.contains(bus_stop_name, case=False) |
                                              bus_stops_df['End'].str.contains(bus_stop_name, case=False)]
            if not filtered_bus_stops_df.empty:
                st.dataframe(filtered_bus_stops_df)
            else:
                st.write('No matching bus stops found.')

        elif option == 'Search Bus Route':
            st.header('Search Bus Route')
            # Text input for bus route number or name
            bus_route_name = st.text_input('Enter Bus Route Number or Name')
            if bus_route_name:
                # Filter bus routes DataFrame based on input
                filtered_bus_routes_df = bus_routes_df[bus_routes_df['Stop_Name'].str.contains(bus_route_name, case=False) |
                                                    bus_routes_df['Last_stop'].str.contains(bus_route_name, case=False) |
                                                    bus_routes_df['From'].str.contains(bus_route_name, case=False)]
                if not filtered_bus_routes_df.empty:
                    st.dataframe(filtered_bus_routes_df)
                else:
                    st.write('No matching bus routes found.')

if __name__=="__main__":
    main()

