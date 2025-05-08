import axios from 'axios';
import { motion } from 'framer-motion';
import { createContext, useContext, useEffect, useState } from 'react';
import { Navigate, Route, BrowserRouter as Router, Routes, useLocation, useNavigate } from 'react-router-dom';
import { ToastContainer, toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import './App.css';

// Configure axios
axios.defaults.baseURL = 'http://localhost:5000';
axios.defaults.headers.common['Content-Type'] = 'application/json';
axios.defaults.withCredentials = true;

// Auth Context
const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [loading, setLoading] = useState(true);
  const [notifications, setNotifications] = useState([]);

  useEffect(() => {
    if (token) {
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
    } else {
      delete axios.defaults.headers.common['Authorization'];
    }
  }, [token]);

  useEffect(() => {
    const fetchUser = async () => {
      try {
        if (token) {
          const res = await axios.get('/api/auth/me');
          setUser(res.data);
          if (res.data.role === 'DONOR' || res.data.role === 'RECEIVER') {
            fetchNotifications(res.data._id);
          }
        }
      } catch (err) {
        console.error("Auth error:", err.response?.data?.message || err.message);
        localStorage.removeItem('token');
        setToken(null);
        setUser(null);
      } finally {
        setLoading(false);
      }
    };

    const fetchNotifications = async (userId) => {
      try {
        const res = await axios.get(`/api/notifications/user/${userId}`);
        setNotifications(res.data);
      } catch (err) {
        console.error("Failed to fetch notifications:", err);
      }
    };

    fetchUser();
  }, [token]);

  const login = async (email, password) => {
    try {
      const res = await axios.post('/api/auth/login', { email, password });
      localStorage.setItem('token', res.data.token);
      setToken(res.data.token);
      setUser(res.data.user);
      if (res.data.user.role === 'DONOR' || res.data.user.role === 'RECEIVER') {
        const notificationsRes = await axios.get(`/api/notifications/user/${res.data.user._id}`);
        setNotifications(notificationsRes.data);
      }
      return res.data.user;
    } catch (err) {
      throw err.response?.data?.message || "Login failed";
    }
  };

  const register = async (userData) => {
    try {
      const res = await axios.post('/api/auth/register', {
        name: userData.name,
        email: userData.email,
        password: userData.password,
        role: userData.role,
        bloodType: userData.bloodType,
        location: userData.location
      });
      localStorage.setItem('token', res.data.token);
      setToken(res.data.token);
      setUser(res.data.user);
      return res.data.user;
    } catch (err) {
      throw err.response?.data?.message || "Registration failed";
    }
  };

  const logout = () => {
    localStorage.removeItem('token');
    setToken(null);
    setUser(null);
    setNotifications([]);
  };

  const addNotification = (notification) => {
    setNotifications(prev => [notification, ...prev]);
  };

  const markNotificationAsRead = async (notificationId) => {
    try {
      await axios.patch(`/api/notifications/${notificationId}/read`);
      setNotifications(prev => 
        prev.map(n => 
          n._id === notificationId ? { ...n, isRead: true } : n
        )
      );
    } catch (err) {
      console.error("Failed to mark notification as read:", err);
    }
  };

  return (
    <AuthContext.Provider value={{ 
      user, 
      token, 
      loading, 
      login, 
      register, 
      logout,
      notifications,
      addNotification,
      markNotificationAsRead
    }}>
      {!loading && children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => useContext(AuthContext);

// Protected Route
const ProtectedRoute = ({ children, roles }) => {
  const { user, loading } = useAuth();
  const location = useLocation();

  if (loading) {
    return <div>Loading...</div>;
  }

  if (!user) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  if (roles && !roles.includes(user.role)) {
    toast.error("Unauthorized access");
    return <Navigate to="/" replace />;
  }

  return typeof children === 'function' 
    ? children({ user }) 
    : children;
};

// Components
const NotificationBell = () => {
  const { notifications, markNotificationAsRead } = useAuth();
  const [isOpen, setIsOpen] = useState(false);
  const unreadCount = notifications.filter(n => !n.isRead).length;

  const handleNotificationClick = (notification) => {
    if (!notification.isRead) {
      markNotificationAsRead(notification._id);
    }
  };

  return (
    <div className="relative">
      <button 
        onClick={() => setIsOpen(!isOpen)}
        className="p-2 rounded-full hover:bg-red-700 relative"
      >
        <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
        </svg>
        {unreadCount > 0 && (
          <span className="absolute top-0 right-0 inline-flex items-center justify-center px-2 py-1 text-xs font-bold leading-none text-red-600 transform translate-x-1/2 -translate-y-1/2 bg-red-500 rounded-full">
            {unreadCount}
          </span>
        )}
      </button>
      
      {isOpen && (
        <div className="absolute right-0 mt-2 w-72 bg-white rounded-md shadow-lg overflow-hidden z-50">
          <div className="py-1">
            <div className="px-4 py-2 border-b border-gray-200 bg-gray-100 text-gray-700 font-semibold">
              Notifications
            </div>
            {notifications.length === 0 ? (
              <div className="px-4 py-3 text-sm text-gray-500">No notifications</div>
            ) : (
              notifications.slice(0, 5).map(notification => (
                <div 
                  key={notification._id} 
                  onClick={() => handleNotificationClick(notification)}
                  className={`px-4 py-3 border-b border-gray-200 cursor-pointer hover:bg-gray-50 ${!notification.isRead ? 'bg-blue-50' : ''}`}
                >
                  <div className="flex justify-between">
                    <span className="font-medium">{notification.title}</span>
                    {!notification.isRead && (
                      <span className="h-2 w-2 rounded-full bg-blue-500"></span>
                    )}
                  </div>
                  <p className="text-sm text-gray-600 mt-1">{notification.message}</p>
                  <p className="text-xs text-gray-500 mt-1">
                    {new Date(notification.createdAt).toLocaleString()}
                  </p>
                </div>
              ))
            )}
            {notifications.length > 5 && (
              <div className="px-4 py-2 text-center text-sm text-blue-600 hover:bg-gray-50 cursor-pointer">
                View all notifications
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

const Navbar = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/login');
    toast.success("Logged out successfully");
  };

  return (
    <nav className="bg-red-600 text-red-600 p-4 shadow-lg w-full">
      <div className="container mx-auto flex justify-between items-center">
        <h1 
          className="text-xl text-white font-bold cursor-pointer" 
          onClick={() => navigate('/')}
        >
          BloodLink
        </h1>
        <div className="flex items-center space-x-6">
          {user ? (
            <>
              <h2 className="hidden md:inline font-medium text-white text-xl">
                Hi, {user.name.split(' ')[0]}
              </h2>
              {user.role === 'DONOR' && (
                <button
                  onClick={() => navigate('/dashboard')}
                  className="px-4 py-2 rounded hover:bg-red-700 transition"
                >
                  Donor Dashboard
                </button>
              )}
              {user.role === 'RECEIVER' && (
                <button
                  onClick={() => navigate('/dashboard')}
                  className="px-4 py-2 rounded hover:bg-red-700 transition"
                >
                  Receiver Dashboard
                </button>
              )}
              {user.role === 'ADMIN' && (
                <button
                  onClick={() => navigate('/admin')}
                  className="px-4 py-2 rounded hover:bg-red-700 transition"
                >
                  Admin Panel
                </button>
              )}
              <button
                onClick={() => navigate('/profile')}
                className="px-4 py-2 rounded hover:bg-red-700 transition"
              >
                Profile
              </button>
              {(user.role === 'DONOR' || user.role === 'RECEIVER') && <NotificationBell />}
              <button
                onClick={handleLogout}
                className="px-4 py-2 bg-white text-red-600 rounded hover:bg-gray-200 transition"
              >
                Logout
              </button>
            </>
          ) : (
            <>
              <button
                onClick={() => navigate('/login')}
                className="px-4 py-2 rounded hover:bg-red-700 transition"
              >
                Login
              </button>
              <button
                onClick={() => navigate('/register')}
                className="px-4 py-2 bg-white text-red-600 rounded hover:bg-gray-200 transition"
              >
                Register
              </button>
            </>
          )}
        </div>
      </div>
    </nav>
  );
};

const LoginForm = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const from = location.state?.from?.pathname || '/dashboard';

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      await login(email, password);
      toast.success("Logged in successfully");
      navigate(from, { replace: true });
    } catch (err) {
      setError(err.toString());
      toast.error(err.toString());
    } finally {
      setLoading(false);
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="max-w-md mx-auto mt-10 p-6 bg-white rounded-lg shadow-md"
    >
      <h2 className="text-2xl font-bold mb-6 text-center text-red-600">Login</h2>
      {error && (
        <div className="mb-4 p-2 bg-red-100 text-red-700 rounded">
          {error}
        </div>
      )}
      <form onSubmit={handleSubmit}>
        <div className="mb-4">
          <label className="block text-gray-700 mb-2" htmlFor="email">
            Email
          </label>
          <input
            type="email"
            id="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="w-full p-2 border rounded focus:outline-none focus:ring-2 focus:ring-red-500"
            required
          />
        </div>
        <div className="mb-6">
          <label className="block text-gray-700 mb-2" htmlFor="password">
            Password
          </label>
          <input
            type="password"
            id="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full p-2 border rounded focus:outline-none focus:ring-2 focus:ring-red-500"
            required
          />
        </div>
        <button
          type="submit"
          disabled={loading}
          className={`w-full bg-red-600 text-red-600 p-2 rounded hover:bg-red-700 transition ${
            loading ? 'opacity-50 cursor-not-allowed' : ''
          }`}
        >
          {loading ? 'Logging in...' : 'Login'}
        </button>
      </form>
      <p className="mt-4 text-center">
        Don't have an account?{' '}
        <span
          className="text-red-600 cursor-pointer hover:underline"
          onClick={() => navigate('/register')}
        >
          Register here
        </span>
      </p>
    </motion.div>
  );
};

const RegisterForm = () => {
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    password: '',
    confirmPassword: '',
    role: 'DONOR',
    bloodType: 'A+',
    location: ''
  });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { register } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const bloodTypes = ['A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-'];
  const cities = ['Dhaka', 'Rajshahi', 'Rangpur', 'Khulna', 'Sylhet', 'Mymensingh', 'Chattogram', 'Barishal'];

  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const role = params.get('role');
    if (role && ['DONOR', 'RECEIVER'].includes(role.toUpperCase())) {
      setFormData(prev => ({ ...prev, role: role.toUpperCase() }));
    }
  }, [location.search]);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    
    if (formData.password !== formData.confirmPassword) {
      setError("Passwords don't match");
      setLoading(false);
      return;
    }

    try {
      await register(formData);
      toast.success("Registration successful!");
      const from = location.state?.from?.pathname || '/dashboard';
      navigate(from, { replace: true });
    } catch (err) {
      setError(err.toString());
      toast.error(err.toString());
    } finally {
      setLoading(false);
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="max-w-md mx-auto mt-10 p-6 bg-white rounded-lg shadow-md"
    >
      <h2 className="text-2xl font-bold mb-6 text-center text-red-600">Register</h2>
      {error && (
        <div className="mb-4 p-2 bg-red-100 text-red-700 rounded">
          {error}
        </div>
      )}
      <form onSubmit={handleSubmit}>
        <div className="mb-4">
          <label className="block text-gray-700 mb-2" htmlFor="name">
            Full Name
          </label>
          <input
            type="text"
            id="name"
            name="name"
            value={formData.name}
            onChange={handleChange}
            className="w-full p-2 border rounded focus:outline-none focus:ring-2 focus:ring-red-500"
            required
          />
        </div>
        <div className="mb-4">
          <label className="block text-gray-700 mb-2" htmlFor="email">
            Email
          </label>
          <input
            type="email"
            id="email"
            name="email"
            value={formData.email}
            onChange={handleChange}
            className="w-full p-2 border rounded focus:outline-none focus:ring-2 focus:ring-red-500"
            required
          />
        </div>
        <div className="mb-4">
          <label className="block text-gray-700 mb-2" htmlFor="password">
            Password
          </label>
          <input
            type="password"
            id="password"
            name="password"
            value={formData.password}
            onChange={handleChange}
            className="w-full p-2 border rounded focus:outline-none focus:ring-2 focus:ring-red-500"
            required
            minLength="6"
          />
        </div>
        <div className="mb-4">
          <label className="block text-gray-700 mb-2" htmlFor="confirmPassword">
            Confirm Password
          </label>
          <input
            type="password"
            id="confirmPassword"
            name="confirmPassword"
            value={formData.confirmPassword}
            onChange={handleChange}
            className="w-full p-2 border rounded focus:outline-none focus:ring-2 focus:ring-red-500"
            required
            minLength="6"
          />
        </div>
        <div className="mb-4">
          <label className="block text-gray-700 mb-2" htmlFor="role">
            I want to:
          </label>
          <select
            id="role"
            name="role"
            value={formData.role}
            onChange={handleChange}
            className="w-full p-2 border rounded focus:outline-none focus:ring-2 focus:ring-red-500"
          >
            <option value="DONOR">Donate Blood</option>
            <option value="RECEIVER">Request Blood</option>
          </select>
        </div>
        {formData.role === 'DONOR' && (
          <>
            <div className="mb-4">
              <label className="block text-gray-700 mb-2" htmlFor="bloodType">
                Blood Type
              </label>
              <select
                id="bloodType"
                name="bloodType"
                value={formData.bloodType}
                onChange={handleChange}
                className="w-full p-2 border rounded focus:outline-none focus:ring-2 focus:ring-red-500"
              >
                {bloodTypes.map(type => (
                  <option key={type} value={type}>{type}</option>
                ))}
              </select>
            </div>
            <div className="mb-4">
              <label className="block text-gray-700 mb-2" htmlFor="location">
                Location (City)
              </label>
              <select
                id="location"
                name="location"
                value={formData.location}
                onChange={handleChange}
                className="w-full p-2 border rounded focus:outline-none focus:ring-2 focus:ring-red-500"
                required
              >
                <option value="">Select your city</option>
                {cities.map(city => (
                  <option key={city} value={city}>{city}</option>
                ))}
              </select>
            </div>
          </>
        )}
        <button
          type="submit"
          disabled={loading}
          className={`w-full bg-red-600 text-red-600 p-2 rounded hover:bg-red-700 transition ${
            loading ? 'opacity-50 cursor-not-allowed' : ''
          }`}
        >
          {loading ? 'Registering...' : 'Register'}
        </button>
      </form>
      <p className="mt-4 text-center">
        Already have an account?{' '}
        <span
          className="text-red-600 cursor-pointer hover:underline"
          onClick={() => navigate('/login')}
        >
          Login here
        </span>
      </p>
    </motion.div>
  );
};

const ProfilePage = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    bloodType: '',
    location: '',
    lastDonationDate: ''
  });
  const [donationHistory, setDonationHistory] = useState([]);
  const [loading, setLoading] = useState({
    profile: false,
    donations: true
  });
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  useEffect(() => {
    if (user) {
      setFormData({
        name: user.name || '',
        email: user.email || '',
        bloodType: user.bloodType || '',
        location: user.location || '',
        lastDonationDate: user.lastDonationDate ? new Date(user.lastDonationDate).toISOString().split('T')[0] : ''
      });

      if (user.role === 'DONOR') {
        fetchDonationHistory();
      }
    }
  }, [user]);

  const fetchDonationHistory = async () => {
    try {
      const res = await axios.get(`/api/donations/${user._id}`);
      setDonationHistory(res.data);
    } catch (err) {
      console.error("Failed to fetch donation history:", err);
      toast.error("Failed to load donation history");
    } finally {
      setLoading(prev => ({ ...prev, donations: false }));
    }
  };

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(prev => ({ ...prev, profile: true }));
    setError('');
    setSuccess('');
    
    try {
      const updateData = {
        name: formData.name,
        location: formData.location,
        lastDonationDate: formData.lastDonationDate ? new Date(formData.lastDonationDate) : null
      };
      
      const res = await axios.put('/api/users/profile', updateData);
      setUser(res.data);
      
      if (user.role === 'DONOR') {
        await fetchDonationHistory();
      }
      
      setSuccess('Profile updated successfully');
      toast.success('Profile updated successfully');
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to update profile');
      toast.error(err.response?.data?.message || 'Failed to update profile');
    } finally {
      setLoading(prev => ({ ...prev, profile: false }));
    }
  };

  const handleLogout = () => {
    logout();
    navigate('/login');
    toast.success('Logged out successfully');
  };

  if (!user) {
    return <Navigate to="/login" />;
  }

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="max-w-3xl mx-auto">
        <h2 className="text-2xl font-bold mb-6 text-red-600">Your Profile</h2>
        
        <div className="bg-white rounded-lg shadow-md p-6">
          {error && (
            <div className="mb-4 p-3 bg-red-100 text-red-700 rounded">
              {error}
            </div>
          )}
          {success && (
            <div className="mb-4 p-3 bg-green-100 text-green-700 rounded">
              {success}
            </div>
          )}
          
          <form onSubmit={handleSubmit}>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <label className="block text-gray-700 mb-2">Full Name</label>
                <input
                  type="text"
                  name="name"
                  value={formData.name}
                  onChange={handleChange}
                  className="w-full p-2 border rounded"
                  required
                />
              </div>
              <div>
                <label className="block text-gray-700 mb-2">Email</label>
                <input
                  type="email"
                  name="email"
                  value={formData.email}
                  className="w-full p-2 border rounded"
                  disabled
                />
              </div>
              {user.role === 'DONOR' && (
                <>
                  <div>
                    <label className="block text-gray-700 mb-2">Blood Type</label>
                    <input
                      type="text"
                      name="bloodType"
                      value={formData.bloodType}
                      className="w-full p-2 border rounded"
                      disabled
                    />
                  </div>
                  <div>
                    <label className="block text-gray-700 mb-2">Location</label>
                    <input
                      type="text"
                      name="location"
                      value={formData.location}
                      onChange={handleChange}
                      className="w-full p-2 border rounded"
                      required
                    />
                  </div>
                  <div>
                    <label className="block text-gray-700 mb-2">Last Donation Date</label>
                    <input
                      type="date"
                      name="lastDonationDate"
                      value={formData.lastDonationDate}
                      onChange={handleChange}
                      className="w-full p-2 border rounded"
                    />
                  </div>
                </>
              )}
            </div>
            
            <div className="mt-6 flex justify-between">
              <button
                type="submit"
                disabled={loading.profile}
                className={`bg-red-600 text-white px-6 py-2 rounded hover:bg-red-700 transition ${
                  loading.profile ? 'opacity-50 cursor-not-allowed' : ''
                }`}
              >
                {loading.profile ? 'Updating...' : 'Update Profile'}
              </button>
              <button
                type="button"
                onClick={handleLogout}
                className="bg-gray-200 text-gray-800 px-6 py-2 rounded hover:bg-gray-300 transition"
              >
                Logout
              </button>
            </div>
          </form>
        </div>

        {user.role === 'DONOR' && (
          <div className="mt-8 bg-white rounded-lg shadow-md p-6">
            <h3 className="text-xl font-semibold mb-4">Donation History</h3>
            {loading.donations ? (
              <div className="flex justify-center items-center h-32">
                <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-red-600"></div>
              </div>
            ) : donationHistory.length === 0 ? (
              <p className="text-gray-600">No donation history found</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="min-w-full">
                  <thead className="bg-gray-100">
                    <tr>
                      <th className="py-2 px-4 text-left">Date</th>
                      <th className="py-2 px-4 text-left">Recipient</th>
                      <th className="py-2 px-4 text-left">Units</th>
                      <th className="py-2 px-4 text-left">Location</th>
                    </tr>
                  </thead>
                  <tbody>
                    {donationHistory.map((donation) => (
                      <tr key={donation._id} className="border-t">
                        <td className="py-2 px-4">
                          {new Date(donation.donationDate).toLocaleDateString()}
                        </td>
                        <td className="py-2 px-4">
                          {donation.requestId?.patientName || 'Anonymous'}
                        </td>
                        <td className="py-2 px-4">{donation.unitsDonated}</td>
                        <td className="py-2 px-4">{donation.location}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

const DonorDashboard = () => {
  const [requests, setRequests] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [filter, setFilter] = useState({
    bloodType: '',
    location: '',
    urgency: ''
  });
  const { user, addNotification } = useAuth();

  useEffect(() => {
    const fetchRequests = async () => {
      try {
        const params = {
          status: 'APPROVED',
          bloodType: user?.bloodType,
          ...filter
        };
        
        Object.keys(params).forEach(key => {
          if (params[key] === '') {
            delete params[key];
          }
        });

        const res = await axios.get('/api/requests', { params });
        setRequests(res.data);
      } catch (err) {
        setError(err.response?.data?.message || 'Failed to fetch requests');
      } finally {
        setLoading(false);
      }
    };

    if (user?.bloodType) {
      fetchRequests();
    }
  }, [user, filter]);

  const handleDonate = async (requestId) => {
    try {
      await axios.post(`/api/requests/${requestId}/donate`);
      
      const request = requests.find(req => req._id === requestId);
      if (request) {
        await axios.post('/api/notifications', {
          userId: request.requester._id,
          title: 'Donation Offer',
          message: `${user.name} has offered to donate blood for your request (${request.patientName})`,
          type: 'DONATION_OFFER'
        });
        addNotification({
          title: 'Donation Confirmed',
          message: `You've offered to donate for ${request.patientName}`,
          type: 'DONATION_CONFIRMATION'
        });
      }

      setRequests(requests.filter(req => req._id !== requestId));
      toast.success("Thank you for your donation offer! The requester has been notified.");
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to process donation');
      toast.error(err.response?.data?.message || 'Failed to process donation');
    }
  };

  const handleFilterChange = (e) => {
    const { name, value } = e.target;
    setFilter(prev => ({ ...prev, [name]: value }));
  };

  if (loading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-red-600"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
        {error}
      </div>
    );
  }

  return (
    <div className="container mx-auto px-4 py-8">
      <h2 className="text-2xl font-bold mb-6 text-red-600">Donor Dashboard</h2>
      
      <div className="mb-8 p-6 bg-blue-50 rounded-lg">
        <h3 className="text-xl font-semibold mb-2">Your Blood Type: {user?.bloodType}</h3>
        <p className="mb-4">You can help save lives by donating blood when matching requests appear.</p>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
          <div>
            <label className="block text-gray-700 mb-1">Filter by Blood Type</label>
            <select
              name="bloodType"
              value={filter.bloodType}
              onChange={handleFilterChange}
              className="w-full p-2 border rounded"
            >
              <option value="">All</option>
              <option value="A+">A+</option>
              <option value="A-">A-</option>
              <option value="B+">B+</option>
              <option value="B-">B-</option>
              <option value="AB+">AB+</option>
              <option value="AB-">AB-</option>
              <option value="O+">O+</option>
              <option value="O-">O-</option>
            </select>
          </div>
          <div>
            <label className="block text-gray-700 mb-1">Filter by Location</label>
            <select
              name="location"
              value={filter.location}
              onChange={handleFilterChange}
              className="w-full p-2 border rounded"
            >
              <option value="">All</option>
              <option value="Dhaka">Dhaka</option>
              <option value="Rajshahi">Rajshahi</option>
              <option value="Rangpur">Rangpur</option>
              <option value="Khulna">Khulna</option>
              <option value="Sylhet">Sylhet</option>
              <option value="Mymensingh">Mymensingh</option>
              <option value="Chattogram">Chattogram</option>
              <option value="Barishal">Barishal</option>
            </select>
          </div>
          <div>
            <label className="block text-gray-700 mb-1">Filter by Urgency</label>
            <select
              name="urgency"
              value={filter.urgency}
              onChange={handleFilterChange}
              className="w-full p-2 border rounded"
            >
              <option value="">All</option>
              <option value="Normal">Normal</option>
              <option value="Urgent">Urgent</option>
              <option value="Emergency">Emergency</option>
            </select>
          </div>
        </div>
      </div>
      
      <h3 className="text-xl font-semibold mb-4">Matching Blood Requests</h3>
      {requests.length === 0 ? (
        <div className="text-center py-12 bg-white rounded-lg shadow">
          <div className="text-red-400 text-5xl mb-4">🩸</div>
          <h3 className="text-xl font-semibold text-gray-800 mb-2">No matching requests found</h3>
          <p className="text-gray-600">Currently there are no blood requests matching your filters.</p>
        </div>
      ) : (
        <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
          {requests.map((request) => (
            <motion.div
              key={request._id}
              whileHover={{ scale: 1.02 }}
              className="border rounded-lg p-6 shadow hover:shadow-md transition bg-white"
            >
              <div className="flex justify-between items-start">
                <div>
                  <h4 className="font-bold text-lg mb-1">{request.patientName}</h4>
                  <p className="text-gray-600">{request.hospital}</p>
                </div>
                <span className={`px-2 py-1 rounded text-xs font-semibold ${
                  request.urgency === 'Emergency' ? 'bg-red-100 text-red-800' :
                  request.urgency === 'Urgent' ? 'bg-orange-100 text-orange-800' :
                  'bg-blue-100 text-blue-800'
                }`}>
                  {request.urgency}
                </span>
              </div>
              <div className="mt-3 flex flex-wrap gap-2 mb-3">
                <span className="bg-red-100 text-red-800 px-3 py-1 rounded-full text-xs font-semibold">
                  {request.bloodType}
                </span>
                <span className="bg-blue-100 text-blue-800 px-3 py-1 rounded-full text-xs font-semibold">
                  {request.unitsRequired} units needed
                </span>
                <span className="bg-green-100 text-green-800 px-3 py-1 rounded-full text-xs font-semibold">
                  {request.location || 'N/A'}
                </span>
              </div>
              <p className="mb-2"><span className="font-semibold">Contact:</span> {request.contactNumber}</p>
              <p className="text-sm text-gray-500">
                Posted: {new Date(request.createdAt).toLocaleDateString()}
              </p>
              <button 
                onClick={() => handleDonate(request._id)}
                className="w-full mt-4 bg-red-600 text-red-600 py-2 rounded hover:bg-red-700 transition"
              >
                I Can Help
              </button>
            </motion.div>
          ))}
        </div>
      )}
    </div>
  );
};

const ReceiverDashboard = () => {
  const [requests, setRequests] = useState([]);
  const [showForm, setShowForm] = useState(false);
  const [formData, setFormData] = useState({
    patientName: '',
    hospital: '',
    bloodType: 'A+',
    unitsRequired: 1,
    urgency: 'Normal',
    contactNumber: '',
    location: '',
    additionalInfo: ''
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const { user, addNotification } = useAuth();

  useEffect(() => {
    const fetchRequests = async () => {
      try {
        const res = await axios.get('/api/requests/user');
        setRequests(res.data);
      } catch (err) {
        setError(err.response?.data?.message || 'Failed to fetch requests');
      } finally {
        setLoading(false);
      }
    };

    fetchRequests();
  }, [user]);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    
    try {
      const res = await axios.post('/api/requests', formData);
      setRequests([res.data, ...requests]);
      setShowForm(false);
      setFormData({
        patientName: '',
        hospital: '',
        bloodType: 'A+',
        unitsRequired: 1,
        urgency: 'Normal',
        contactNumber: '',
        location: '',
        additionalInfo: ''
      });
      toast.success("Blood request submitted successfully!");
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to create request');
      toast.error(err.response?.data?.message || 'Failed to create request');
    } finally {
      setLoading(false);
    }
  };

  const cancelRequest = async (requestId) => {
    try {
      await axios.delete(`/api/requests/${requestId}`);
      setRequests(requests.filter(req => req._id !== requestId));
      toast.success("Request cancelled successfully");
    } catch (err) {
      toast.error(err.response?.data?.message || 'Failed to cancel request');
    }
  };

  if (loading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-red-600"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
        {error}
      </div>
    );
  }

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="flex justify-between items-center mb-8">
        <h2 className="text-2xl font-bold text-red-600">Receiver Dashboard</h2>
        <button
          onClick={() => setShowForm(!showForm)}
          className="bg-red-600 text-red-600 px-6 py-2 rounded hover:bg-red-700 transition"
        >
          {showForm ? 'Cancel' : 'New Request'}
        </button>
      </div>

      {showForm && (
        <motion.div
          initial={{ opacity: 0, height: 0 }}
          animate={{ opacity: 1, height: 'auto' }}
          className="mb-8 p-6 bg-white rounded-lg shadow-md"
        >
          <h3 className="text-xl font-semibold mb-4">New Blood Request</h3>
          <form onSubmit={handleSubmit}>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <label className="block text-gray-700 mb-1">Patient Name</label>
                <input
                  type="text"
                  name="patientName"
                  value={formData.patientName}
                  onChange={handleChange}
                  className="w-full p-2 border rounded"
                  required
                />
              </div>
              <div>
                <label className="block text-gray-700 mb-1">Hospital</label>
                <input
                  type="text"
                  name="hospital"
                  value={formData.hospital}
                  onChange={handleChange}
                  className="w-full p-2 border rounded"
                  required
                />
              </div>
              <div>
                <label className="block text-gray-700 mb-1">Blood Type</label>
                <select
                  name="bloodType"
                  value={formData.bloodType}
                  onChange={handleChange}
                  className="w-full p-2 border rounded"
                >
                  <option value="A+">A+</option>
                  <option value="A-">A-</option>
                  <option value="B+">B+</option>
                  <option value="B-">B-</option>
                  <option value="AB+">AB+</option>
                  <option value="AB-">AB-</option>
                  <option value="O+">O+</option>
                  <option value="O-">O-</option>
                </select>
              </div>
              <div>
                <label className="block text-gray-700 mb-1">Units Required</label>
                <input
                  type="number"
                  name="unitsRequired"
                  min="1"
                  value={formData.unitsRequired}
                  onChange={handleChange}
                  className="w-full p-2 border rounded"
                  required
                />
              </div>
              <div>
                <label className="block text-gray-700 mb-1">Urgency</label>
                <select
                  name="urgency"
                  value={formData.urgency}
                  onChange={handleChange}
                  className="w-full p-2 border rounded"
                >
                  <option value="Normal">Normal</option>
                  <option value="Urgent">Urgent</option>
                  <option value="Emergency">Emergency</option>
                </select>
              </div>
              <div>
                <label className="block text-gray-700 mb-1">Location</label>
                <input
                  type="text"
                  name="location"
                  value={formData.location}
                  onChange={handleChange}
                  className="w-full p-2 border rounded"
                  required
                />
              </div>
              <div className="md:col-span-2">
                <label className="block text-gray-700 mb-1">Contact Number</label>
                <input
                  type="tel"
                  name="contactNumber"
                  value={formData.contactNumber}
                  onChange={handleChange}
                  className="w-full p-2 border rounded"
                  required
                />
              </div>
              <div className="md:col-span-2">
                <label className="block text-gray-700 mb-1">Additional Information</label>
                <textarea
                  name="additionalInfo"
                  value={formData.additionalInfo}
                  onChange={handleChange}
                  className="w-full p-2 border rounded"
                  rows="3"
                ></textarea>
              </div>
            </div>
            <div className="mt-6 flex justify-end gap-4">
              <button
                type="button"
                onClick={() => setShowForm(false)}
                className="bg-gray-200 text-gray-800 px-6 py-2 rounded hover:bg-gray-300 transition"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={loading}
                className={`bg-red-600 text-red-600 px-6 py-2 rounded hover:bg-red-700 transition ${
                  loading ? 'opacity-50 cursor-not-allowed' : ''
                }`}
              >
                {loading ? 'Submitting...' : 'Submit Request'}
              </button>
            </div>
          </form>
        </motion.div>
      )}

      <h3 className="text-xl font-semibold mb-6">Your Blood Requests</h3>
      {requests.length === 0 ? (
        <div className="text-center py-12 bg-white rounded-lg shadow">
          <div className="text-red-400 text-5xl mb-4">🩸</div>
          <h3 className="text-xl font-semibold text-gray-800 mb-2">No blood requests yet</h3>
          <p className="text-gray-600">Create your first blood request using the button above</p>
        </div>
      ) : (
        <div className="grid gap-6">
          {requests.map((request) => (
            <motion.div
              key={request._id}
              whileHover={{ scale: 1.01 }}
              className="border rounded-lg p-6 shadow hover:shadow-md transition bg-white"
            >
              <div className="flex justify-between items-start">
                <div>
                  <h4 className="font-bold text-lg">{request.patientName}</h4>
                  <p className="text-gray-600">{request.hospital}</p>
                </div>
                <div className="flex items-center gap-2">
                  <span
                    className={`px-3 py-1 rounded-full text-xs font-semibold ${
                      request.status === 'PENDING'
                        ? 'bg-yellow-100 text-yellow-800'
                        : request.status === 'APPROVED'
                        ? 'bg-green-100 text-green-800'
                        : 'bg-red-100 text-red-800'
                    }`}
                  >
                    {request.status}
                  </span>
                  {request.status === 'PENDING' && (
                    <button
                      onClick={() => cancelRequest(request._id)}
                      className="text-red-600 hover:text-red-800"
                      title="Cancel Request"
                    >
                      <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                        <path fillRule="evenodd" d="M9 2a1 1 0 00-.894.553L7.382 4H4a1 1 0 000 2v10a2 2 0 002 2h8a2 2 0 002-2V6a1 1 0 100-2h-3.382l-.724-1.447A1 1 0 0011 2H9zM7 8a1 1 0 012 0v6a1 1 0 11-2 0V8zm5-1a1 1 0 00-1 1v6a1 1 0 102 0V8a1 1 0 00-1-1z" clipRule="evenodd" />
                      </svg>
                    </button>
                  )}
                </div>
              </div>
              <div className="mt-3 flex flex-wrap gap-2">
                <span className="bg-red-100 text-red-800 px-3 py-1 rounded-full text-xs font-semibold">
                  {request.bloodType}
                </span>
                <span className="bg-blue-100 text-blue-800 px-3 py-1 rounded-full text-xs font-semibold">
                  {request.unitsRequired} units
                </span>
                <span className="bg-purple-100 text-purple-800 px-3 py-1 rounded-full text-xs font-semibold">
                  {request.urgency}
                </span>
                {request.location && (
                  <span className="bg-green-100 text-green-800 px-3 py-1 rounded-full text-xs font-semibold">
                    {request.location}
                  </span>
                )}
              </div>
              <p className="mt-3">
                <span className="font-semibold">Contact:</span> {request.contactNumber}
              </p>
              {request.additionalInfo && (
                <p className="mt-2">
                  <span className="font-semibold">Notes:</span> {request.additionalInfo}
                </p>
              )}
              <p className="text-sm text-gray-500 mt-2">
                Requested on: {new Date(request.createdAt).toLocaleString()}
              </p>
              {request.donor && (
                <div className="mt-3 p-3 bg-blue-50 rounded">
                  <p className="font-semibold">Donor: {request.donor.name}</p>
                </div>
              )}
            </motion.div>
          ))}
        </div>
      )}
    </div>
  );
};

const AdminDashboard = () => {
  const [users, setUsers] = useState([]);
  const [requests, setRequests] = useState([]);
  const [stats, setStats] = useState({
    totalUsers: 0,
    totalDonors: 0,
    totalReceivers: 0,
    totalRequests: 0,
    completedRequests: 0
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [activeTab, setActiveTab] = useState('requests');

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [usersRes, requestsRes, statsRes] = await Promise.all([
          axios.get('/api/users'),
          axios.get('/api/requests/all'),
          axios.get('/api/stats')
        ]);
        setUsers(usersRes.data);
        setRequests(requestsRes.data);
        setStats(statsRes.data);
      } catch (err) {
        setError(err.response?.data?.message || 'Failed to fetch data');
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, []);

  const updateRequestStatus = async (id, status) => {
    try {
      await axios.put(`/api/requests/${id}`, { status });
      setRequests(requests.map(req => 
        req._id === id ? { ...req, status } : req
      ));
      toast.success("Request status updated successfully");
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to update request');
      toast.error(err.response?.data?.message || 'Failed to update request');
    }
  };

  const deleteUser = async (userId) => {
    try {
      await axios.delete(`/api/users/${userId}`);
      setUsers(users.filter(user => user._id !== userId));
      toast.success("User deleted successfully");
    } catch (err) {
      toast.error(err.response?.data?.message || 'Failed to delete user');
    }
  };

  const deleteRequest = async (requestId) => {
    try {
      await axios.delete(`/api/requests/admin/${requestId}`);
      setRequests(requests.filter(req => req._id !== requestId));
      toast.success("Request deleted successfully");
    } catch (err) {
      toast.error(err.response?.data?.message || 'Failed to delete request');
    }
  };

  if (loading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-red-600"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
        {error}
      </div>
    );
  }

  return (
    <div className="container mx-auto px-4 py-8">
      <h2 className="text-2xl font-bold mb-6 text-red-600">Admin Dashboard</h2>
      
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4 mb-8">
        <div className="bg-white p-4 rounded-lg shadow">
          <h3 className="text-gray-500 text-sm font-medium">Total Users</h3>
          <p className="text-2xl font-bold">{stats.totalUsers}</p>
        </div>
        <div className="bg-white p-4 rounded-lg shadow">
          <h3 className="text-gray-500 text-sm font-medium">Donors</h3>
          <p className="text-2xl font-bold">{stats.totalDonors}</p>
        </div>
        <div className="bg-white p-4 rounded-lg shadow">
          <h3 className="text-gray-500 text-sm font-medium">Receivers</h3>
          <p className="text-2xl font-bold">{stats.totalReceivers}</p>
        </div>
        <div className="bg-white p-4 rounded-lg shadow">
          <h3 className="text-gray-500 text-sm font-medium">Total Requests</h3>
          <p className="text-2xl font-bold">{stats.totalRequests}</p>
        </div>
        <div className="bg-white p-4 rounded-lg shadow">
          <h3 className="text-gray-500 text-sm font-medium">Completed</h3>
          <p className="text-2xl font-bold">{stats.completedRequests}</p>
        </div>
      </div>

      <div className="mb-6 border-b border-gray-200">
        <nav className="-mb-px flex space-x-8">
          <button
            onClick={() => setActiveTab('requests')}
            className={`py-4 px-1 border-b-2 font-medium text-sm ${
              activeTab === 'requests'
                ? 'border-red-500 text-red-600'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            }`}
          >
            Blood Requests
          </button>
          <button
            onClick={() => setActiveTab('users')}
            className={`py-4 px-1 border-b-2 font-medium text-sm ${
              activeTab === 'users'
                ? 'border-red-500 text-red-600'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            }`}
          >
            Users
          </button>
        </nav>
      </div>

      {activeTab === 'requests' ? (
        <div>
          <h3 className="text-xl font-semibold mb-4">All Blood Requests</h3>
          {requests.length === 0 ? (
            <div className="text-center py-12 bg-white rounded-lg shadow">
              <div className="text-red-400 text-5xl mb-4">🩸</div>
              <h3 className="text-xl font-semibold text-gray-800 mb-2">No blood requests found</h3>
              <p className="text-gray-600">There are currently no blood requests in the system.</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="min-w-full bg-white rounded-lg overflow-hidden">
                <thead className="bg-gray-100">
                  <tr>
                    <th className="py-3 px-4 text-left">Patient</th>
                    <th className="py-3 px-4 text-left">Hospital</th>
                    <th className="py-3 px-4 text-left">Blood Type</th>
                    <th className="py-3 px-4 text-left">Units</th>
                    <th className="py-3 px-4 text-left">Requester</th>
                    <th className="py-3 px-4 text-left">Status</th>
                    <th className="py-3 px-4 text-left">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {requests.map((request) => (
                    <tr key={request._id} className="border-t hover:bg-gray-50">
                      <td className="py-3 px-4">{request.patientName}</td>
                      <td className="py-3 px-4">{request.hospital}</td>
                      <td className="py-3 px-4">{request.bloodType}</td>
                      <td className="py-3 px-4">{request.unitsRequired}</td>
                      <td className="py-3 px-4">{request.requester?.name || 'Unknown'}</td>
                      <td className="py-3 px-4">
                        <select
                          value={request.status}
                          onChange={(e) => updateRequestStatus(request._id, e.target.value)}
                          className="border rounded px-2 py-1 text-sm"
                        >
                          <option value="PENDING">Pending</option>
                          <option value="APPROVED">Approved</option>
                          <option value="REJECTED">Rejected</option>
                          <option value="COMPLETED">Completed</option>
                        </select>
                      </td>
                      <td className="py-3 px-4">
                        <button
                          onClick={() => deleteRequest(request._id)}
                          className="text-red-600 hover:text-red-800"
                        >
                          Delete
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      ) : (
        <div>
          <h3 className="text-xl font-semibold mb-4">All Users</h3>
          <div className="overflow-x-auto">
            <table className="min-w-full bg-white rounded-lg overflow-hidden">
              <thead className="bg-gray-100">
                <tr>
                  <th className="py-3 px-4 text-left">Name</th>
                  <th className="py-3 px-4 text-left">Email</th>
                  <th className="py-3 px-4 text-left">Role</th>
                  <th className="py-3 px-4 text-left">Blood Type</th>
                  <th className="py-3 px-4 text-left">Location</th>
                  <th className="py-3 px-4 text-left">Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map((user) => (
                  <tr key={user._id} className="border-t hover:bg-gray-50">
                    <td className="py-3 px-4">{user.name}</td>
                    <td className="py-3 px-4">{user.email}</td>
                    <td className="py-3 px-4 capitalize">{user.role.toLowerCase()}</td>
                    <td className="py-3 px-4">{user.bloodType || '-'}</td>
                    <td className="py-3 px-4">{user.location || '-'}</td>
                    <td className="py-3 px-4">
                      <button
                        onClick={() => deleteUser(user._id)}
                        className="text-red-600 hover:text-red-800"
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};

const HomePage = () => {
  const navigate = useNavigate();

  return (
    <div className="bg-gradient-to-r from-red-50 to-white">
      <div className="container mx-auto px-4 py-16">
        <div className="flex flex-col items-center text-center">
          <motion.h1
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            className="text-4xl md:text-5xl font-bold text-red-600 mb-6"
          >
            Save Lives With BloodLink System
          </motion.h1>
          <p className="text-lg text-gray-700 mb-8 max-w-lg">
            Connecting blood donors with those in need. Join our community to help save lives today. Every donation can make a difference.
          </p>
          <div className="flex flex-col sm:flex-row gap-4">
            <button 
              onClick={() => navigate('/register?role=DONOR')}
              className="bg-white text-red-600 px-6 py-3 rounded-lg hover:bg-red-700 transition shadow-md"
            >
              Become a Donor
            </button>
            <button 
              onClick={() => navigate('/register?role=RECEIVER')}
              className="bg-white text-red-600 px-6 py-3 rounded-lg border border-red-600 hover:bg-red-50 transition shadow-md"
            >
              Request Blood
            </button>
          </div>
        </div>
      </div>

      <div className="bg-white py-16">
        <div className="container mx-auto px-4">
          <h2 className="text-3xl font-bold text-center text-red-600 mb-12">How It Works</h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            <motion.div
              whileHover={{ scale: 1.05 }}
              className="bg-white p-6 rounded-lg shadow-md text-center"
            >
              <div className="bg-red-100 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-4">
                <span className="text-red-600 text-2xl">1</span>
              </div>
              <h3 className="text-xl font-semibold mb-2">Register</h3>
              <p className="text-gray-600">Sign up as a donor or receiver in just a few simple steps.</p>
            </motion.div>
            <motion.div
              whileHover={{ scale: 1.05 }}
              className="bg-white p-6 rounded-lg shadow-md text-center"
            >
              <div className="bg-red-100 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-4">
                <span className="text-red-600 text-2xl">2</span>
              </div>
              <h3 className="text-xl font-semibold mb-2">Connect</h3>
              <p className="text-gray-600">Donors and receivers are matched based on blood type and location.</p>
            </motion.div>
            <motion.div
              whileHover={{ scale: 1.05 }}
              className="bg-white p-6 rounded-lg shadow-md text-center"
            >
              <div className="bg-red-100 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-4">
                <span className="text-red-600 text-2xl">3</span>
              </div>
              <h3 className="text-xl font-semibold mb-2">Save Lives</h3>
              <p className="text-gray-600">Complete the donation process and help save lives in your community.</p>
            </motion.div>
          </div>
        </div>
      </div>

      <div className="bg-gray-50 py-16">
        <div className="container mx-auto px-4">
          <h2 className="text-3xl font-bold text-center text-red-600 mb-12">Blood Donation Facts</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            <div className="bg-white p-6 rounded-lg shadow-md">
              <h3 className="text-xl font-semibold mb-2 text-red-600">Every 2 Seconds</h3>
              <p className="text-gray-600">Someone in the Bangladesh needs blood.</p>
            </div>
            <div className="bg-white p-6 rounded-lg shadow-md">
              <h3 className="text-xl font-semibold mb-2 text-red-600">1 Donation</h3>
              <p className="text-gray-600">Can save up to 3 lives.</p>
            </div>
            <div className="bg-white p-6 rounded-lg shadow-md">
              <h3 className="text-xl font-semibold mb-2 text-red-600">38%</h3>
              <p className="text-gray-600">Of the Bangladesh population is eligible to donate, less than 10% do annually.</p>
            </div>
            <div className="bg-white p-6 rounded-lg shadow-md">
              <h3 className="text-xl font-semibold mb-2 text-red-600">56 Days</h3>
              <p className="text-gray-600">How often you can donate whole blood.</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

// App Router
const App = () => {
  return (
    <Router>
      <AuthProvider>
        <div className="min-h-screen bg-gray-50 flex flex-col">
          <Navbar />
          <main className="flex-grow">
            <ToastContainer position="top-right" autoClose={5000} />
            <Routes>
              <Route path="/" element={<HomePage />} />
              <Route path="/login" element={<LoginForm />} />
              <Route path="/register" element={<RegisterForm />} />
              <Route path="/profile" element={
                <ProtectedRoute>
                  <ProfilePage />
                </ProtectedRoute>
              } />
              <Route path="/dashboard" element={
                <ProtectedRoute>
                  {({ user }) => (
                    user.role === 'DONOR' ? <DonorDashboard /> : 
                    user.role === 'RECEIVER' ? <ReceiverDashboard /> : 
                    <Navigate to="/admin" />
                  )}
                </ProtectedRoute>
              } />
              <Route path="/admin" element={
                <ProtectedRoute roles={['ADMIN']}>
                  <AdminDashboard />
                </ProtectedRoute>
              } />
            </Routes>
          </main>
          <footer className="bg-gray-100 py-8">
            <div className="container mx-auto px-4">
              <div className="flex flex-col md:flex-row justify-between items-center">
                <div className="mb-4 md:mb-0">
                  <p className="text-gray-600">Connecting donors with those in need</p>
                </div>
                <div className="flex space-x-6">
                  <a href="#" className="text-gray-600 hover:text-red-600">About</a>
                  <a href="#" className="text-gray-600 hover:text-red-600">FAQ</a>
                  <a href="#" className="text-gray-600 hover:text-red-600">Contact</a>
                  <a href="#" className="text-gray-600 hover:text-red-600">Privacy Policy</a>
                </div>
              </div>
              <div className="mt-6 pt-6 border-t border-gray-200 text-center text-gray-500">
                <p>© {new Date().getFullYear()} BloodLink. All rights reserved.</p>
              </div>
            </div>
          </footer>
        </div>
      </AuthProvider>
    </Router>
  );
};

export default App;