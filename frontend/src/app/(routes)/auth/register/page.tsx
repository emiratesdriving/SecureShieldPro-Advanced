'use client';'use client';'use client';



import { useState } from 'react';

import { useRouter } from 'next/navigation';

import Link from 'next/link';import { useState } from 'react';import { useState } from 'react';

import { EyeIcon, EyeSlashIcon } from '@heroicons/react/24/outline';

import { useRouter } from 'next/navigation';import { useRouter } from 'next/navigation';

export default function RegisterPage() {

  const [formData, setFormData] = useState({import Link from 'next/link';import Link from 'next/link';

    first_name: '',

    last_name: '',import { EyeIcon, EyeSlashIcon } from '@heroicons/react/24/outline';import AuthLayout from '@/components/AuthLayout';

    email: '',

    password: '',import { EyeIcon, EyeSlashIcon } from '@heroicons/react/24/outline';

    confirmPassword: '',

  });export default function RegisterPage() {



  const [isLoading, setIsLoading] = useState(false);  const [formData, setFormData] = useState({export default function RegisterPage() {

  const [error, setError] = useState('');

  const [showPassword, setShowPassword] = useState(false);    first_name: '',  const [formData, setFormData] = useState({

  const [showConfirmPassword, setShowConfirmPassword] = useState(false);

    last_name: '',    first_name: '',

  const router = useRouter();

    email: '',    last_name: '',

  const passwordRequirements = {

    length: formData.password.length >= 8,    password: '',    email: '',

    uppercase: /[A-Z]/.test(formData.password),

    lowercase: /[a-z]/.test(formData.password),    confirmPassword: '',    password: '',

    number: /\d/.test(formData.password),

    special: /[!@#$%^&*(),.?":{}|<>]/.test(formData.password),  });    confirmPassword: '',

  };

  });

  const allRequirementsMet = Object.values(passwordRequirements).every(Boolean);

  const passwordsMatch = formData.password === formData.confirmPassword && formData.confirmPassword !== '';  const [isLoading, setIsLoading] = useState(false);



  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {  const [error, setError] = useState('');  const [formData, setFormData] = useState({import Link from "next/link";import Link from 'next/link'

    const { name, value } = e.target;

    setFormData(prev => ({  const [showPassword, setShowPassword] = useState(false);

      ...prev,

      [name]: value  const [showConfirmPassword, setShowConfirmPassword] = useState(false);  const [isLoading, setIsLoading] = useState(false);

    }));

    

    if (error) setError('');

  };  const router = useRouter();  const [error, setError] = useState("");    first_name: "",



  const handleSubmit = async (e: React.FormEvent) => {

    e.preventDefault();

      const passwordRequirements = {  const [showPassword, setShowPassword] = useState(false);

    if (!allRequirementsMet) {

      setError('Please meet all password requirements');    length: formData.password.length >= 8,

      return;

    }    uppercase: /[A-Z]/.test(formData.password),  const [showConfirmPassword, setShowConfirmPassword] = useState(false);    last_name: "",import AuthLayout from "@/components/AuthLayout";import { EyeIcon, EyeSlashIcon } from '@heroicons/react/24/outline'



    if (!passwordsMatch) {    lowercase: /[a-z]/.test(formData.password),

      setError('Passwords do not match');

      return;    number: /\d/.test(formData.password),  const router = useRouter();

    }

    special: /[!@#$%^&*(),.?":{}|<>]/.test(formData.password),

    setIsLoading(true);

    setError('');  };    email: "",



    try {

      const response = await fetch('http://localhost:8000/api/v1/auth/register', {

        method: 'POST',  const allRequirementsMet = Object.values(passwordRequirements).every(Boolean);  const passwordRequirements = {

        headers: {

          'Content-Type': 'application/json',  const passwordsMatch = formData.password === formData.confirmPassword && formData.confirmPassword !== '';

        },

        body: JSON.stringify({    length: formData.password.length >= 8,    password: "",

          first_name: formData.first_name,

          last_name: formData.last_name,  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {

          email: formData.email,

          password: formData.password,    const { name, value } = e.target;    uppercase: /[A-Z]/.test(formData.password),

        }),

      });    setFormData(prev => ({



      const data = await response.json();      ...prev,    lowercase: /[a-z]/.test(formData.password),    confirmPassword: ""



      if (!response.ok) {      [name]: value

        throw new Error(data.detail || 'Registration failed');

      }    }));    number: /\d/.test(formData.password),



      // Store authentication data    

      localStorage.setItem('token', data.access_token);

      localStorage.setItem('user', JSON.stringify({    if (error) setError('');    special: /[!@#$%^&*(),.?":{}|<>]/.test(formData.password),  });export default function RegisterPage() {export default function RegisterPage() {

        id: data.user.id,

        email: data.user.email,  };

        first_name: data.user.first_name,

        last_name: data.user.last_name,  };

      }));

  const handleSubmit = async (e: React.FormEvent) => {

      // Redirect to dashboard

      router.push('/dashboard');    e.preventDefault();  const [isLoading, setIsLoading] = useState(false);

    } catch (err) {

      setError(err instanceof Error ? err.message : 'Registration failed');    

    } finally {

      setIsLoading(false);    if (!allRequirementsMet) {  const allRequirementsMet = Object.values(passwordRequirements).every(Boolean);

    }

  };      setError('Please meet all password requirements');



  return (      return;  const passwordsMatch = formData.password === formData.confirmPassword && formData.confirmPassword !== "";  const [error, setError] = useState("");  const [formData, setFormData] = useState({  const [formData, setFormData] = useState({

    <div className="min-h-screen bg-gradient-to-br from-blue-900 via-purple-900 to-pink-800 flex items-center justify-center p-4">

      <div className="max-w-md w-full">    }

        <div className="text-center mb-8">

          <div className="flex items-center justify-center mb-4">

            <div className="w-12 h-12 bg-blue-600 rounded-lg flex items-center justify-center">

              <div className="w-8 h-8 bg-blue-400 rounded-full flex items-center justify-center">    if (!passwordsMatch) {

                <div className="w-4 h-4 bg-white rounded-full"></div>

              </div>      setError('Passwords do not match');  const handleSubmit = async (e: React.FormEvent) => {  const [showPassword, setShowPassword] = useState(false);

            </div>

            <span className="ml-3 text-2xl font-bold text-white">SecureShield Pro</span>      return;

          </div>

        </div>    }    e.preventDefault();



        <div className="bg-white/10 backdrop-blur-xl rounded-2xl p-8 border border-white/20">

          <div className="text-center mb-6">

            <h1 className="text-2xl font-bold text-white mb-2">Create Account</h1>    setIsLoading(true);    setIsLoading(true);  const [showConfirmPassword, setShowConfirmPassword] = useState(false);    first_name: "",    email: '',

            <p className="text-gray-300">Join SecureShield Pro to protect your organization</p>

          </div>    setError('');



          {error && (    setError("");

            <div className="mb-4 p-3 bg-red-500/20 border border-red-400/50 rounded-lg">

              <p className="text-red-200 text-sm">{error}</p>    try {

            </div>

          )}      const response = await fetch('http://localhost:8000/api/v1/auth/register', {  const router = useRouter();



          <form onSubmit={handleSubmit} className="space-y-4">        method: 'POST',

            <div className="grid grid-cols-2 gap-4">

              <div>        headers: {    if (!allRequirementsMet) {

                <label htmlFor="first_name" className="block text-sm font-medium text-gray-200 mb-2">

                  First Name          'Content-Type': 'application/json',

                </label>

                <input        },      setError("Password does not meet all requirements");    last_name: "",    username: '',

                  id="first_name"

                  name="first_name"        body: JSON.stringify({

                  type="text"

                  required          first_name: formData.first_name,      setIsLoading(false);

                  value={formData.first_name}

                  onChange={handleInputChange}          last_name: formData.last_name,

                  className="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"

                  placeholder="John"          email: formData.email,      return;  const passwordRequirements = {

                />

              </div>          password: formData.password,

              <div>

                <label htmlFor="last_name" className="block text-sm font-medium text-gray-200 mb-2">        }),    }

                  Last Name

                </label>      });

                <input

                  id="last_name"    length: formData.password.length >= 8,    email: "",    password: '',

                  name="last_name"

                  type="text"      const data = await response.json();

                  required

                  value={formData.last_name}    if (!passwordsMatch) {

                  onChange={handleInputChange}

                  className="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"      if (!response.ok) {

                  placeholder="Doe"

                />        throw new Error(data.detail || 'Registration failed');      setError("Passwords do not match");    uppercase: /[A-Z]/.test(formData.password),

              </div>

            </div>      }



            <div>      setIsLoading(false);

              <label htmlFor="email" className="block text-sm font-medium text-gray-200 mb-2">

                Email Address      // Store authentication data

              </label>

              <input      localStorage.setItem('token', data.access_token);      return;    lowercase: /[a-z]/.test(formData.password),    password: "",    confirmPassword: '',

                id="email"

                name="email"      localStorage.setItem('user', JSON.stringify({

                type="email"

                required        id: data.user.id,    }

                value={formData.email}

                onChange={handleInputChange}        email: data.user.email,

                className="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"

                placeholder="john@company.com"        first_name: data.user.first_name,    number: /\d/.test(formData.password),

              />

            </div>        last_name: data.user.last_name,



            <div>      }));    try {

              <label htmlFor="password" className="block text-sm font-medium text-gray-200 mb-2">

                Password

              </label>

              <div className="relative">      // Redirect to dashboard      const response = await fetch("http://localhost:8000/api/v1/users/register", {    special: /[!@#$%^&*(),.?":{}|<>]/.test(formData.password)    confirmPassword: ""    full_name: ''

                <input

                  id="password"      router.push('/dashboard');

                  name="password"

                  type={showPassword ? 'text' : 'password'}    } catch (err) {        method: "POST",

                  required

                  value={formData.password}      setError(err instanceof Error ? err.message : 'Registration failed');

                  onChange={handleInputChange}

                  className="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent pr-12"    } finally {        headers: {  };

                  placeholder="Create a strong password"

                />      setIsLoading(false);

                <button

                  type="button"    }          "Content-Type": "application/json",

                  onClick={() => setShowPassword(!showPassword)}

                  className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-white"  };

                >

                  {showPassword ? (        },  });  })

                    <EyeSlashIcon className="h-5 w-5" />

                  ) : (  return (

                    <EyeIcon className="h-5 w-5" />

                  )}    <div className="min-h-screen bg-gradient-to-br from-blue-900 via-purple-900 to-pink-800 flex items-center justify-center p-4">        body: JSON.stringify({

                </button>

              </div>      <div className="max-w-md w-full">

            </div>

        {/* Logo */}          email: formData.email,  const allRequirementsMet = Object.values(passwordRequirements).every(Boolean);

            <div>

              <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-200 mb-2">        <div className="text-center mb-8">

                Confirm Password

              </label>          <div className="flex items-center justify-center mb-4">          password: formData.password,

              <div className="relative">

                <input            <div className="w-12 h-12 bg-blue-600 rounded-lg flex items-center justify-center">

                  id="confirmPassword"

                  name="confirmPassword"              <div className="w-8 h-8 bg-blue-400 rounded-full flex items-center justify-center">          first_name: formData.first_name,  const passwordsMatch = formData.password === formData.confirmPassword && formData.confirmPassword !== "";  const [isLoading, setIsLoading] = useState(false);  const [showPassword, setShowPassword] = useState(false)

                  type={showConfirmPassword ? 'text' : 'password'}

                  required                <div className="w-4 h-4 bg-white rounded-full"></div>

                  value={formData.confirmPassword}

                  onChange={handleInputChange}              </div>          last_name: formData.last_name,

                  className="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent pr-12"

                  placeholder="Confirm your password"            </div>

                />

                <button            <span className="ml-3 text-2xl font-bold text-white">SecureShield Pro</span>        }),

                  type="button"

                  onClick={() => setShowConfirmPassword(!showConfirmPassword)}          </div>

                  className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-white"

                >        </div>      });

                  {showConfirmPassword ? (

                    <EyeSlashIcon className="h-5 w-5" />

                  ) : (

                    <EyeIcon className="h-5 w-5" />        {/* Registration Form */}  const handleSubmit = async (e: React.FormEvent) => {  const [error, setError] = useState("");  const [showConfirmPassword, setShowConfirmPassword] = useState(false)

                  )}

                </button>        <div className="bg-white/10 backdrop-blur-xl rounded-2xl p-8 border border-white/20">

              </div>

            </div>          <div className="text-center mb-6">      const data = await response.json();



            <button            <h1 className="text-2xl font-bold text-white mb-2">Create Account</h1>

              type="submit"

              disabled={isLoading || !allRequirementsMet || !passwordsMatch}            <p className="text-gray-300">Join SecureShield Pro to protect your organization</p>    e.preventDefault();

              className="w-full py-3 px-4 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white font-semibold rounded-lg transition-colors"

            >          </div>

              {isLoading ? 'Creating Account...' : 'Create Account'}

            </button>      if (response.ok) {

          </form>

          {error && (

          <div className="mt-6 text-center">

            <p className="text-gray-300">            <div className="mb-4 p-3 bg-red-500/20 border border-red-400/50 rounded-lg">        // Store the token    setIsLoading(true);  const [showPassword, setShowPassword] = useState(false);  const [loading, setLoading] = useState(false)

              Already have an account?{' '}

              <Link              <p className="text-red-200 text-sm">{error}</p>

                href="/auth/login"

                className="text-blue-400 hover:text-blue-300 font-semibold"            </div>        localStorage.setItem("token", data.access_token);

              >

                Sign in          )}

              </Link>

            </p>        localStorage.setItem("user", JSON.stringify(data.user));    setError("");

          </div>

        </div>          <form onSubmit={handleSubmit} className="space-y-4">

      </div>

    </div>            <div className="grid grid-cols-2 gap-4">        

  );

}              <div>

                <label htmlFor="first_name" className="block text-sm font-medium text-gray-200 mb-2">        // Redirect to dashboard  const [showConfirmPassword, setShowConfirmPassword] = useState(false);  const [error, setError] = useState('')

                  First Name

                </label>        router.push("/dashboard");

                <input

                  id="first_name"      } else {    if (!allRequirementsMet) {

                  name="first_name"

                  type="text"        setError(data.detail || "Registration failed");

                  required

                  value={formData.first_name}      }      setError("Password does not meet all requirements");  const router = useRouter();  const [success, setSuccess] = useState('')

                  onChange={handleInputChange}

                  className="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"    } catch (error) {

                  placeholder="John"

                />      setError("Network error. Please try again.");      setIsLoading(false);

              </div>

              <div>    } finally {

                <label htmlFor="last_name" className="block text-sm font-medium text-gray-200 mb-2">

                  Last Name      setIsLoading(false);      return;  const router = useRouter()

                </label>

                <input    }

                  id="last_name"

                  name="last_name"  };    }

                  type="text"

                  required

                  value={formData.last_name}

                  onChange={handleInputChange}  return (  const passwordRequirements = {

                  className="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"

                  placeholder="Doe"    <AuthLayout>

                />

              </div>      <div className="w-full max-w-md">    if (!passwordsMatch) {

            </div>

        <div className="text-center mb-8">

            <div>

              <label htmlFor="email" className="block text-sm font-medium text-gray-200 mb-2">          <h1 className="text-3xl font-bold text-white mb-2">Create Account</h1>      setError("Passwords do not match");    length: formData.password.length >= 8,  const handleSubmit = async (e: React.FormEvent) => {

                Email Address

              </label>          <p className="text-gray-300">Join SecureShield Pro for advanced security</p>

              <input

                id="email"        </div>      setIsLoading(false);

                name="email"

                type="email"

                required

                value={formData.email}        <form onSubmit={handleSubmit} className="space-y-6">      return;    uppercase: /[A-Z]/.test(formData.password),    e.preventDefault()

                onChange={handleInputChange}

                className="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"          {error && (

                placeholder="john@company.com"

              />            <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3">    }

            </div>

              <p className="text-red-400 text-sm">{error}</p>

            <div>

              <label htmlFor="password" className="block text-sm font-medium text-gray-200 mb-2">            </div>    lowercase: /[a-z]/.test(formData.password),    setLoading(true)

                Password

              </label>          )}

              <div className="relative">

                <input    try {

                  id="password"

                  name="password"          {/* Name Fields */}

                  type={showPassword ? 'text' : 'password'}

                  required          <div className="grid grid-cols-2 gap-4">      const response = await fetch("http://localhost:8000/api/v1/users/register", {    number: /\d/.test(formData.password),    setError('')

                  value={formData.password}

                  onChange={handleInputChange}            <div>

                  className="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent pr-12"

                  placeholder="Create a strong password"              <label className="block text-sm font-medium text-gray-300 mb-2">        method: "POST",

                />

                <button                First Name

                  type="button"

                  onClick={() => setShowPassword(!showPassword)}              </label>        headers: {    special: /[!@#$%^&*(),.?":{}|<>]/.test(formData.password)    setSuccess('')

                  className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-white"

                >              <input

                  {showPassword ? (

                    <EyeSlashIcon className="h-5 w-5" />                type="text"          "Content-Type": "application/json",

                  ) : (

                    <EyeIcon className="h-5 w-5" />                required

                  )}

                </button>                className="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-lg focus:outline-none focus:border-blue-400 text-white placeholder-gray-400"        },  };

              </div>

                              placeholder="John"

              {/* Password Requirements */}

              {formData.password && (                value={formData.first_name}        body: JSON.stringify({

                <div className="mt-2 p-3 bg-white/5 rounded-lg">

                  <p className="text-xs text-gray-300 mb-2">Password must contain:</p>                onChange={(e) =>

                  <div className="grid grid-cols-2 gap-1 text-xs">

                    <div className={`flex items-center ${passwordRequirements.length ? 'text-green-400' : 'text-gray-400'}`}>                  setFormData({ ...formData, first_name: e.target.value })          first_name: formData.first_name,    // Validate passwords match

                      <span className="mr-1">{passwordRequirements.length ? '✓' : '○'}</span>

                      8+ characters                }

                    </div>

                    <div className={`flex items-center ${passwordRequirements.uppercase ? 'text-green-400' : 'text-gray-400'}`}>              />          last_name: formData.last_name,

                      <span className="mr-1">{passwordRequirements.uppercase ? '✓' : '○'}</span>

                      Uppercase            </div>

                    </div>

                    <div className={`flex items-center ${passwordRequirements.lowercase ? 'text-green-400' : 'text-gray-400'}`}>            <div>          email: formData.email,  const allRequirementsMet = Object.values(passwordRequirements).every(Boolean);    if (formData.password !== formData.confirmPassword) {

                      <span className="mr-1">{passwordRequirements.lowercase ? '✓' : '○'}</span>

                      Lowercase              <label className="block text-sm font-medium text-gray-300 mb-2">

                    </div>

                    <div className={`flex items-center ${passwordRequirements.number ? 'text-green-400' : 'text-gray-400'}`}>                Last Name          password: formData.password

                      <span className="mr-1">{passwordRequirements.number ? '✓' : '○'}</span>

                      Number              </label>

                    </div>

                    <div className={`flex items-center ${passwordRequirements.special ? 'text-green-400' : 'text-gray-400'} col-span-2`}>              <input        }),  const passwordsMatch = formData.password === formData.confirmPassword && formData.confirmPassword !== "";      setError('Passwords do not match')

                      <span className="mr-1">{passwordRequirements.special ? '✓' : '○'}</span>

                      Special character                type="text"

                    </div>

                  </div>                required      });

                </div>

              )}                className="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-lg focus:outline-none focus:border-blue-400 text-white placeholder-gray-400"

            </div>

                placeholder="Doe"      setLoading(false)

            <div>

              <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-200 mb-2">                value={formData.last_name}

                Confirm Password

              </label>                onChange={(e) =>      const data = await response.json();

              <div className="relative">

                <input                  setFormData({ ...formData, last_name: e.target.value })

                  id="confirmPassword"

                  name="confirmPassword"                }  const handleSubmit = async (e: React.FormEvent) => {      return

                  type={showConfirmPassword ? 'text' : 'password'}

                  required              />

                  value={formData.confirmPassword}

                  onChange={handleInputChange}            </div>      if (response.ok) {

                  className={`w-full px-4 py-3 bg-white/10 border rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent pr-12 ${

                    formData.confirmPassword && !passwordsMatch          </div>

                      ? 'border-red-400/50'

                      : 'border-white/20'        // Store token and user info    e.preventDefault();    }

                  }`}

                  placeholder="Confirm your password"          {/* Email */}

                />

                <button          <div>        localStorage.setItem("token", data.access_token);

                  type="button"

                  onClick={() => setShowConfirmPassword(!showConfirmPassword)}            <label className="block text-sm font-medium text-gray-300 mb-2">

                  className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-white"

                >              Email Address        localStorage.setItem("user", JSON.stringify(data.user));    setIsLoading(true);

                  {showConfirmPassword ? (

                    <EyeSlashIcon className="h-5 w-5" />            </label>

                  ) : (

                    <EyeIcon className="h-5 w-5" />            <input        

                  )}

                </button>              type="email"

              </div>

              {formData.confirmPassword && !passwordsMatch && (              required        // Redirect to dashboard    setError("");    try {

                <p className="mt-1 text-xs text-red-400">Passwords do not match</p>

              )}              className="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-lg focus:outline-none focus:border-blue-400 text-white placeholder-gray-400"

            </div>

              placeholder="john.doe@company.com"        router.push("/dashboard");

            <button

              type="submit"              value={formData.email}

              disabled={isLoading || !allRequirementsMet || !passwordsMatch}

              className="w-full py-3 px-4 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white font-semibold rounded-lg transition-colors"              onChange={(e) =>      } else {      const response = await fetch('/api/v1/auth/register', {

            >

              {isLoading ? 'Creating Account...' : 'Create Account'}                setFormData({ ...formData, email: e.target.value })

            </button>

          </form>              }        setError(data.detail || "Registration failed");



          <div className="mt-6 text-center">            />

            <p className="text-gray-300">

              Already have an account?{' '}          </div>      }    if (!allRequirementsMet) {        method: 'POST',

              <Link

                href="/auth/login"

                className="text-blue-400 hover:text-blue-300 font-semibold"

              >          {/* Password */}    } catch (error) {

                Sign in

              </Link>          <div>

            </p>

          </div>            <label className="block text-sm font-medium text-gray-300 mb-2">      setError("Network error. Please try again.");      setError("Password does not meet all requirements");        headers: {

        </div>

      </div>              Password

    </div>

  );            </label>    } finally {

}
            <div className="relative">

              <input      setIsLoading(false);      setIsLoading(false);          'Content-Type': 'application/json',

                type={showPassword ? "text" : "password"}

                required    }

                className="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-lg focus:outline-none focus:border-blue-400 text-white placeholder-gray-400 pr-12"

                placeholder="Create a strong password"  };      return;        },

                value={formData.password}

                onChange={(e) =>

                  setFormData({ ...formData, password: e.target.value })

                }  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {    }        body: JSON.stringify({

              />

              <button    setFormData(prev => ({

                type="button"

                className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-white"      ...prev,          email: formData.email,

                onClick={() => setShowPassword(!showPassword)}

              >      [e.target.name]: e.target.value

                {showPassword ? (

                  <EyeSlashIcon className="h-5 w-5" />    }));    if (!passwordsMatch) {          username: formData.username,

                ) : (

                  <EyeIcon className="h-5 w-5" />  };

                )}

              </button>      setError("Passwords do not match");          password: formData.password,

            </div>

  return (

            {/* Password Requirements */}

            {formData.password && (    <AuthLayout       setIsLoading(false);          full_name: formData.full_name || null

              <div className="mt-3 p-3 bg-white/5 rounded-lg">

                <p className="text-xs text-gray-300 mb-2">Password must contain:</p>      title="Create Account" 

                <div className="grid grid-cols-2 gap-2 text-xs">

                  <div className={passwordRequirements.length ? "text-green-400" : "text-gray-400"}>      subtitle="Join SecureShield Pro and secure your digital world"      return;        }),

                    ✓ At least 8 characters

                  </div>    >

                  <div className={passwordRequirements.uppercase ? "text-green-400" : "text-gray-400"}>

                    ✓ Uppercase letter      <form onSubmit={handleSubmit} className="space-y-6">    }      })

                  </div>

                  <div className={passwordRequirements.lowercase ? "text-green-400" : "text-gray-400"}>        {error && (

                    ✓ Lowercase letter

                  </div>          <div className="bg-red-500/20 border border-red-500/50 rounded-xl p-4 text-red-100 text-sm">

                  <div className={passwordRequirements.number ? "text-green-400" : "text-gray-400"}>

                    ✓ Number            {error}

                  </div>

                  <div className={passwordRequirements.special ? "text-green-400" : "text-gray-400"}>          </div>    try {      if (response.ok) {

                    ✓ Special character

                  </div>        )}

                </div>

              </div>      const response = await fetch("/api/v1/users/register", {        setSuccess('Account created successfully! Redirecting to login...')

            )}

          </div>        {/* Name Fields */}



          {/* Confirm Password */}        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">        method: "POST",        setTimeout(() => {

          <div>

            <label className="block text-sm font-medium text-gray-300 mb-2">          <div>

              Confirm Password

            </label>            <label htmlFor="first_name" className="block text-sm font-medium text-blue-100 mb-2">        headers: {          router.push('/auth/login')

            <div className="relative">

              <input              First Name

                type={showConfirmPassword ? "text" : "password"}

                required            </label>          "Content-Type": "application/json",        }, 2000)

                className="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-lg focus:outline-none focus:border-blue-400 text-white placeholder-gray-400 pr-12"

                placeholder="Confirm your password"            <input

                value={formData.confirmPassword}

                onChange={(e) =>              id="first_name"        },      } else {

                  setFormData({ ...formData, confirmPassword: e.target.value })

                }              name="first_name"

              />

              <button              type="text"        body: JSON.stringify({        const error = await response.json()

                type="button"

                className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-white"              value={formData.first_name}

                onClick={() => setShowConfirmPassword(!showConfirmPassword)}

              >              onChange={handleChange}          first_name: formData.first_name,        setError(error.detail || 'Registration failed')

                {showConfirmPassword ? (

                  <EyeSlashIcon className="h-5 w-5" />              required

                ) : (

                  <EyeIcon className="h-5 w-5" />              className="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-xl text-white placeholder-blue-200/50 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200"          last_name: formData.last_name,      }

                )}

              </button>              placeholder="John"

            </div>

            {formData.confirmPassword && (            />          email: formData.email,    } catch (err) {

              <div className="mt-1">

                {passwordsMatch ? (          </div>

                  <p className="text-green-400 text-xs">✓ Passwords match</p>

                ) : (          <div>          password: formData.password      setError('Network error. Please try again.')

                  <p className="text-red-400 text-xs">✗ Passwords do not match</p>

                )}            <label htmlFor="last_name" className="block text-sm font-medium text-blue-100 mb-2">

              </div>

            )}              Last Name        }),    } finally {

          </div>

            </label>

          {/* Submit Button */}

          <button            <input      });      setLoading(false)

            type="submit"

            disabled={isLoading || !allRequirementsMet || !passwordsMatch}              id="last_name"

            className="w-full bg-gradient-to-r from-blue-600 to-purple-600 text-white py-3 px-4 rounded-lg font-medium hover:from-blue-700 hover:to-purple-700 transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"

          >              name="last_name"    }

            {isLoading ? "Creating Account..." : "Create Account"}

          </button>              type="text"

        </form>

              value={formData.last_name}      const data = await response.json();  }

        {/* Login Link */}

        <div className="mt-6 text-center">              onChange={handleChange}

          <p className="text-gray-300">

            Already have an account?{" "}              required

            <Link href="/auth/login" className="text-blue-400 hover:text-blue-300">

              Sign in              className="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-xl text-white placeholder-blue-200/50 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200"

            </Link>

          </p>              placeholder="Doe"      if (response.ok) {  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {

        </div>

            />

        {/* OAuth Options */}

        <div className="mt-8">          </div>        // Store token and user info    setFormData(prev => ({

          <div className="relative">

            <div className="absolute inset-0 flex items-center">        </div>

              <div className="w-full border-t border-white/20"></div>

            </div>        localStorage.setItem("token", data.access_token);      ...prev,

            <div className="relative flex justify-center text-sm">

              <span className="px-2 bg-transparent text-gray-400">Or continue with</span>        {/* Email Field */}

            </div>

          </div>        <div>        localStorage.setItem("user", JSON.stringify(data.user));      [e.target.name]: e.target.value



          <div className="mt-6 grid grid-cols-2 gap-3">          <label htmlFor="email" className="block text-sm font-medium text-blue-100 mb-2">

            <button

              type="button"            Email Address            }))

              className="w-full inline-flex justify-center py-3 px-4 border border-white/20 rounded-lg bg-white/5 text-sm font-medium text-gray-300 hover:bg-white/10 transition-colors"

              onClick={() => {/* Handle Google OAuth */}}          </label>

            >

              <svg className="w-5 h-5" viewBox="0 0 24 24">          <div className="relative">        // Redirect to dashboard  }

                <path

                  fill="currentColor"            <input

                  d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"

                />              id="email"        router.push("/dashboard");

                <path

                  fill="currentColor"              name="email"

                  d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"

                />              type="email"      } else {  return (

                <path

                  fill="currentColor"              value={formData.email}

                  d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"

                />              onChange={handleChange}        setError(data.detail || "Registration failed");    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 py-12">

                <path

                  fill="currentColor"              required

                  d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"

                />              className="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-xl text-white placeholder-blue-200/50 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200"      }      {/* Background pattern */}

              </svg>

              <span className="ml-2">Google</span>              placeholder="your@email.com"

            </button>

            />    } catch (error) {      <div className="absolute inset-0 opacity-20">

            <button

              type="button"            <div className="absolute inset-y-0 right-0 pr-3 flex items-center pointer-events-none">

              className="w-full inline-flex justify-center py-3 px-4 border border-white/20 rounded-lg bg-white/5 text-sm font-medium text-gray-300 hover:bg-white/10 transition-colors"

              onClick={() => {/* Handle GitHub OAuth */}}              <svg className="w-5 h-5 text-blue-300/50" fill="none" stroke="currentColor" viewBox="0 0 24 24">      setError("Network error. Please try again.");        <div className="w-full h-full bg-repeat" style={{

            >

              <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 12a4 4 0 10-8 0 4 4 0 008 0zm0 0v1.5a2.5 2.5 0 005 0V12a9 9 0 10-9 9m4.5-1.206a8.959 8.959 0 01-4.5 1.207" />

                <path

                  fillRule="evenodd"              </svg>    } finally {          backgroundImage: `url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%239C92AC' fill-opacity='0.1'%3E%3Ccircle cx='7' cy='7' r='7'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E")`

                  d="M10 0C4.477 0 0 4.484 0 10.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0110 4.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.203 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.942.359.31.678.921.678 1.856 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0020 10.017C20 4.484 15.522 0 10 0z"

                  clipRule="evenodd"            </div>

                />

              </svg>          </div>      setIsLoading(false);        }}></div>

              <span className="ml-2">GitHub</span>

            </button>        </div>

          </div>

        </div>    }      </div>

      </div>

    </AuthLayout>        {/* Password Field */}

  );

}        <div>  };      

          <label htmlFor="password" className="block text-sm font-medium text-blue-100 mb-2">

            Password      <div className="relative w-full max-w-md">

          </label>

          <div className="relative">  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {        {/* Glassmorphism container */}

            <input

              id="password"    setFormData(prev => ({        <div className="backdrop-blur-xl bg-white/10 border border-white/20 rounded-2xl p-8 shadow-2xl">

              name="password"

              type={showPassword ? "text" : "password"}      ...prev,          {/* Logo and title */}

              value={formData.password}

              onChange={handleChange}      [e.target.name]: e.target.value          <div className="text-center mb-8">

              required

              className="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-xl text-white placeholder-blue-200/50 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200"    }));            <div className="inline-flex items-center justify-center w-16 h-16 bg-gradient-to-r from-purple-500 to-pink-500 rounded-full mb-4">

              placeholder="Create a strong password"

            />  };              <svg className="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">

            <button

              type="button"                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18 9v3m0 0v3m0-3h3m-3 0h-3m-2-5a4 4 0 11-8 0 4 4 0 018 0zM3 20a6 6 0 0112 0v1H3v-1z" />

              onClick={() => setShowPassword(!showPassword)}

              className="absolute inset-y-0 right-0 pr-3 flex items-center text-blue-300/50 hover:text-blue-200 transition-colors"  return (              </svg>

            >

              {showPassword ? (    <AuthLayout             </div>

                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">

                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.878 9.878L8.464 8.464M14.12 14.12l1.415 1.415M9.878 9.878L8.464 8.464M14.12 14.12l1.415 1.415M21 12c0 5.523-4.477 10-10 10S1 17.523 1 12 5.477 2 11 2s10 4.477 10 10z" />      title="Create Account"             <h1 className="text-3xl font-bold text-white mb-2">Join SecureShield Pro</h1>

                </svg>

              ) : (      subtitle="Join SecureShield Pro and secure your digital world"            <p className="text-white/70">Create your security dashboard account</p>

                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">

                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />    >          </div>

                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />

                </svg>      <form onSubmit={handleSubmit} className="space-y-6">

              )}

            </button>        {error && (          {/* Success message */}

          </div>

          <div className="bg-red-500/20 border border-red-500/50 rounded-xl p-4 text-red-100 text-sm">          {success && (

          {/* Password Requirements */}

          {formData.password && (            {error}            <div className="mb-6 p-4 bg-green-500/20 border border-green-500/30 rounded-lg">

            <div className="mt-3 space-y-2">

              <div className="text-xs text-blue-100/80">Password requirements:</div>          </div>              <p className="text-green-200 text-sm">{success}</p>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">

                <div className={`flex items-center ${passwordRequirements.length ? 'text-green-400' : 'text-blue-200/60'}`}>        )}            </div>

                  <svg className={`w-3 h-3 mr-1 ${passwordRequirements.length ? 'text-green-400' : 'text-blue-200/60'}`} fill="currentColor" viewBox="0 0 20 20">

                    <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />          )}

                  </svg>

                  8+ characters        {/* Name Fields */}

                </div>

                <div className={`flex items-center ${passwordRequirements.uppercase ? 'text-green-400' : 'text-blue-200/60'}`}>        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">          {/* Error message */}

                  <svg className={`w-3 h-3 mr-1 ${passwordRequirements.uppercase ? 'text-green-400' : 'text-blue-200/60'}`} fill="currentColor" viewBox="0 0 20 20">

                    <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />          <div>          {error && (

                  </svg>

                  Uppercase letter            <label htmlFor="first_name" className="block text-sm font-medium text-blue-100 mb-2">            <div className="mb-6 p-4 bg-red-500/20 border border-red-500/30 rounded-lg">

                </div>

                <div className={`flex items-center ${passwordRequirements.lowercase ? 'text-green-400' : 'text-blue-200/60'}`}>              First Name              <p className="text-red-200 text-sm">{error}</p>

                  <svg className={`w-3 h-3 mr-1 ${passwordRequirements.lowercase ? 'text-green-400' : 'text-blue-200/60'}`} fill="currentColor" viewBox="0 0 20 20">

                    <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />            </label>            </div>

                  </svg>

                  Lowercase letter            <input          )}

                </div>

                <div className={`flex items-center ${passwordRequirements.number ? 'text-green-400' : 'text-blue-200/60'}`}>              id="first_name"

                  <svg className={`w-3 h-3 mr-1 ${passwordRequirements.number ? 'text-green-400' : 'text-blue-200/60'}`} fill="currentColor" viewBox="0 0 20 20">

                    <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />              name="first_name"          {/* Register form */}

                  </svg>

                  Number              type="text"          <form onSubmit={handleSubmit} className="space-y-6">

                </div>

                <div className={`flex items-center ${passwordRequirements.special ? 'text-green-400' : 'text-blue-200/60'} md:col-span-2`}>              value={formData.first_name}            <div>

                  <svg className={`w-3 h-3 mr-1 ${passwordRequirements.special ? 'text-green-400' : 'text-blue-200/60'}`} fill="currentColor" viewBox="0 0 20 20">

                    <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />              onChange={handleChange}              <label htmlFor="full_name" className="block text-sm font-medium text-white/90 mb-2">

                  </svg>

                  Special character (!@#$%^&*...)              required                Full Name (Optional)

                </div>

              </div>              className="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-xl text-white placeholder-blue-200/50 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200"              </label>

            </div>

          )}              placeholder="John"              <input

        </div>

            />                type="text"

        {/* Confirm Password Field */}

        <div>          </div>                id="full_name"

          <label htmlFor="confirmPassword" className="block text-sm font-medium text-blue-100 mb-2">

            Confirm Password          <div>                name="full_name"

          </label>

          <div className="relative">            <label htmlFor="last_name" className="block text-sm font-medium text-blue-100 mb-2">                value={formData.full_name}

            <input

              id="confirmPassword"              Last Name                onChange={handleChange}

              name="confirmPassword"

              type={showConfirmPassword ? "text" : "password"}            </label>                className="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-white/50 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent backdrop-blur-sm"

              value={formData.confirmPassword}

              onChange={handleChange}            <input                placeholder="Enter your full name"

              required

              className={`w-full px-4 py-3 bg-white/10 border rounded-xl text-white placeholder-blue-200/50 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200 ${              id="last_name"              />

                formData.confirmPassword && !passwordsMatch 

                  ? 'border-red-500/50'               name="last_name"            </div>

                  : formData.confirmPassword && passwordsMatch 

                    ? 'border-green-500/50'               type="text"

                    : 'border-white/20'

              }`}              value={formData.last_name}            <div>

              placeholder="Confirm your password"

            />              onChange={handleChange}              <label htmlFor="email" className="block text-sm font-medium text-white/90 mb-2">

            <button

              type="button"              required                Email Address

              onClick={() => setShowConfirmPassword(!showConfirmPassword)}

              className="absolute inset-y-0 right-0 pr-3 flex items-center text-blue-300/50 hover:text-blue-200 transition-colors"              className="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-xl text-white placeholder-blue-200/50 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200"              </label>

            >

              {showConfirmPassword ? (              placeholder="Doe"              <input

                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">

                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.878 9.878L8.464 8.464M14.12 14.12l1.415 1.415M9.878 9.878L8.464 8.464M14.12 14.12l1.415 1.415M21 12c0 5.523-4.477 10-10 10S1 17.523 1 12 5.477 2 11 2s10 4.477 10 10z" />            />                type="email"

                </svg>

              ) : (          </div>                id="email"

                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">

                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />        </div>                name="email"

                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />

                </svg>                value={formData.email}

              )}

            </button>        {/* Email Field */}                onChange={handleChange}

          </div>

          {formData.confirmPassword && !passwordsMatch && (        <div>                className="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-white/50 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent backdrop-blur-sm"

            <div className="mt-2 text-xs text-red-400">Passwords do not match</div>

          )}          <label htmlFor="email" className="block text-sm font-medium text-blue-100 mb-2">                placeholder="Enter your email"

          {passwordsMatch && formData.confirmPassword && (

            <div className="mt-2 text-xs text-green-400">Passwords match</div>            Email Address                required

          )}

        </div>          </label>              />



        {/* Terms & Conditions */}          <div className="relative">            </div>

        <div className="flex items-start space-x-3">

          <input            <input

            type="checkbox"

            required              id="email"            <div>

            className="w-4 h-4 text-blue-600 bg-white/10 border-white/20 rounded focus:ring-blue-500 focus:ring-2 mt-1"

          />              name="email"              <label htmlFor="username" className="block text-sm font-medium text-white/90 mb-2">

          <div className="text-sm text-blue-100/80">

            I agree to the{" "}              type="email"                Username

            <Link href="/terms" className="text-blue-300 hover:text-blue-200 transition-colors">

              Terms of Service              value={formData.email}              </label>

            </Link>{" "}

            and{" "}              onChange={handleChange}              <input

            <Link href="/privacy" className="text-blue-300 hover:text-blue-200 transition-colors">

              Privacy Policy              required                type="text"

            </Link>

          </div>              className="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-xl text-white placeholder-blue-200/50 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200"                id="username"

        </div>

              placeholder="your@email.com"                name="username"

        {/* Submit Button */}

        <button            />                value={formData.username}

          type="submit"

          disabled={isLoading || !allRequirementsMet || !passwordsMatch}            <div className="absolute inset-y-0 right-0 pr-3 flex items-center pointer-events-none">                onChange={handleChange}

          className="w-full bg-gradient-to-r from-blue-600 to-purple-600 text-white font-semibold py-3 px-4 rounded-xl hover:from-blue-700 hover:to-purple-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:ring-offset-transparent transition-all duration-200 transform hover:scale-105 disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none"

        >              <svg className="w-5 h-5 text-blue-300/50" fill="none" stroke="currentColor" viewBox="0 0 24 24">                className="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-white/50 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent backdrop-blur-sm"

          {isLoading ? (

            <div className="flex items-center justify-center">                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 12a4 4 0 10-8 0 4 4 0 008 0zm0 0v1.5a2.5 2.5 0 005 0V12a9 9 0 10-9 9m4.5-1.206a8.959 8.959 0 01-4.5 1.207" />                placeholder="Choose a username"

              <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">

                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>              </svg>                required

                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>

              </svg>            </div>                minLength={3}

              Creating account...

            </div>          </div>              />

          ) : (

            "Create Account"        </div>            </div>

          )}

        </button>



        {/* Sign In Link */}        {/* Password Field */}            <div>

        <div className="text-center">

          <span className="text-blue-100/60">Already have an account? </span>        <div>              <label htmlFor="password" className="block text-sm font-medium text-white/90 mb-2">

          <Link 

            href="/auth/login"           <label htmlFor="password" className="block text-sm font-medium text-blue-100 mb-2">                Password

            className="text-blue-300 hover:text-blue-200 font-medium transition-colors"

          >            Password              </label>

            Sign in

          </Link>          </label>              <div className="relative">

        </div>

      </form>          <div className="relative">                <input

    </AuthLayout>

  );            <input                  type={showPassword ? 'text' : 'password'}

}
              id="password"                  id="password"

              name="password"                  name="password"

              type={showPassword ? "text" : "password"}                  value={formData.password}

              value={formData.password}                  onChange={handleChange}

              onChange={handleChange}                  className="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-white/50 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent backdrop-blur-sm pr-12"

              required                  placeholder="Create a strong password"

              className="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-xl text-white placeholder-blue-200/50 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200"                  required

              placeholder="Create a strong password"                  minLength={8}

            />                />

            <button                <button

              type="button"                  type="button"

              onClick={() => setShowPassword(!showPassword)}                  onClick={() => setShowPassword(!showPassword)}

              className="absolute inset-y-0 right-0 pr-3 flex items-center text-blue-300/50 hover:text-blue-200 transition-colors"                  className="absolute right-3 top-1/2 transform -translate-y-1/2 text-white/60 hover:text-white"

            >                >

              {showPassword ? (                  {showPassword ? (

                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">                    <EyeSlashIcon className="w-5 h-5" />

                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.878 9.878L8.464 8.464M14.12 14.12l1.415 1.415M9.878 9.878L8.464 8.464M14.12 14.12l1.415 1.415M21 12c0 5.523-4.477 10-10 10S1 17.523 1 12 5.477 2 11 2s10 4.477 10 10z" />                  ) : (

                </svg>                    <EyeIcon className="w-5 h-5" />

              ) : (                  )}

                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">                </button>

                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />              </div>

                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />            </div>

                </svg>

              )}            <div>

            </button>              <label htmlFor="confirmPassword" className="block text-sm font-medium text-white/90 mb-2">

          </div>                Confirm Password

              </label>

          {/* Password Requirements */}              <div className="relative">

          {formData.password && (                <input

            <div className="mt-3 space-y-2">                  type={showConfirmPassword ? 'text' : 'password'}

              <div className="text-xs text-blue-100/80">Password requirements:</div>                  id="confirmPassword"

              <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">                  name="confirmPassword"

                <div className={`flex items-center ${passwordRequirements.length ? 'text-green-400' : 'text-blue-200/60'}`}>                  value={formData.confirmPassword}

                  <svg className={`w-3 h-3 mr-1 ${passwordRequirements.length ? 'text-green-400' : 'text-blue-200/60'}`} fill="currentColor" viewBox="0 0 20 20">                  onChange={handleChange}

                    <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />                  className="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-white/50 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent backdrop-blur-sm pr-12"

                  </svg>                  placeholder="Confirm your password"

                  8+ characters                  required

                </div>                />

                <div className={`flex items-center ${passwordRequirements.uppercase ? 'text-green-400' : 'text-blue-200/60'}`}>                <button

                  <svg className={`w-3 h-3 mr-1 ${passwordRequirements.uppercase ? 'text-green-400' : 'text-blue-200/60'}`} fill="currentColor" viewBox="0 0 20 20">                  type="button"

                    <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />                  onClick={() => setShowConfirmPassword(!showConfirmPassword)}

                  </svg>                  className="absolute right-3 top-1/2 transform -translate-y-1/2 text-white/60 hover:text-white"

                  Uppercase letter                >

                </div>                  {showConfirmPassword ? (

                <div className={`flex items-center ${passwordRequirements.lowercase ? 'text-green-400' : 'text-blue-200/60'}`}>                    <EyeSlashIcon className="w-5 h-5" />

                  <svg className={`w-3 h-3 mr-1 ${passwordRequirements.lowercase ? 'text-green-400' : 'text-blue-200/60'}`} fill="currentColor" viewBox="0 0 20 20">                  ) : (

                    <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />                    <EyeIcon className="w-5 h-5" />

                  </svg>                  )}

                  Lowercase letter                </button>

                </div>              </div>

                <div className={`flex items-center ${passwordRequirements.number ? 'text-green-400' : 'text-blue-200/60'}`}>            </div>

                  <svg className={`w-3 h-3 mr-1 ${passwordRequirements.number ? 'text-green-400' : 'text-blue-200/60'}`} fill="currentColor" viewBox="0 0 20 20">

                    <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />            {/* Password requirements */}

                  </svg>            <div className="text-xs text-white/60 space-y-1">

                  Number              <p>Password must contain:</p>

                </div>              <ul className="list-disc list-inside space-y-1 pl-2">

                <div className={`flex items-center ${passwordRequirements.special ? 'text-green-400' : 'text-blue-200/60'} md:col-span-2`}>                <li>At least 8 characters</li>

                  <svg className={`w-3 h-3 mr-1 ${passwordRequirements.special ? 'text-green-400' : 'text-blue-200/60'}`} fill="currentColor" viewBox="0 0 20 20">                <li>One uppercase letter</li>

                    <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />                <li>One lowercase letter</li>

                  </svg>                <li>One number</li>

                  Special character (!@#$%^&*...)                <li>One special character</li>

                </div>              </ul>

              </div>            </div>

            </div>

          )}            <button

        </div>              type="submit"

              disabled={loading}

        {/* Confirm Password Field */}              className="w-full py-3 px-4 bg-gradient-to-r from-purple-500 to-pink-500 text-white font-semibold rounded-lg shadow-lg hover:from-purple-600 hover:to-pink-600 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:ring-offset-2 focus:ring-offset-transparent transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"

        <div>            >

          <label htmlFor="confirmPassword" className="block text-sm font-medium text-blue-100 mb-2">              {loading ? (

            Confirm Password                <div className="flex items-center justify-center">

          </label>                  <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-2"></div>

          <div className="relative">                  Creating account...

            <input                </div>

              id="confirmPassword"              ) : (

              name="confirmPassword"                'Create Account'

              type={showConfirmPassword ? "text" : "password"}              )}

              value={formData.confirmPassword}            </button>

              onChange={handleChange}          </form>

              required

              className={`w-full px-4 py-3 bg-white/10 border rounded-xl text-white placeholder-blue-200/50 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200 ${          {/* Footer */}

                formData.confirmPassword && !passwordsMatch           <div className="mt-8 text-center">

                  ? 'border-red-500/50'             <p className="text-white/70 text-sm">

                  : formData.confirmPassword && passwordsMatch               Already have an account?{' '}

                    ? 'border-green-500/50'               <Link href="/auth/login" className="text-purple-400 hover:text-purple-300 font-medium">

                    : 'border-white/20'                Sign in

              }`}              </Link>

              placeholder="Confirm your password"            </p>

            />          </div>

            <button        </div>

              type="button"

              onClick={() => setShowConfirmPassword(!showConfirmPassword)}        {/* Additional security info */}

              className="absolute inset-y-0 right-0 pr-3 flex items-center text-blue-300/50 hover:text-blue-200 transition-colors"        <div className="mt-8 text-center">

            >          <p className="text-white/50 text-xs">

              {showConfirmPassword ? (            Protected by enterprise-grade security • End-to-end encryption

                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">          </p>

                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.878 9.878L8.464 8.464M14.12 14.12l1.415 1.415M9.878 9.878L8.464 8.464M14.12 14.12l1.415 1.415M21 12c0 5.523-4.477 10-10 10S1 17.523 1 12 5.477 2 11 2s10 4.477 10 10z" />        </div>

                </svg>      </div>

              ) : (    </div>

                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">  )

                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />}
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                </svg>
              )}
            </button>
          </div>
          {formData.confirmPassword && !passwordsMatch && (
            <div className="mt-2 text-xs text-red-400">Passwords do not match</div>
          )}
          {passwordsMatch && formData.confirmPassword && (
            <div className="mt-2 text-xs text-green-400">Passwords match</div>
          )}
        </div>

        {/* Terms & Conditions */}
        <div className="flex items-start space-x-3">
          <input
            type="checkbox"
            required
            className="w-4 h-4 text-blue-600 bg-white/10 border-white/20 rounded focus:ring-blue-500 focus:ring-2 mt-1"
          />
          <div className="text-sm text-blue-100/80">
            I agree to the{" "}
            <Link href="/terms" className="text-blue-300 hover:text-blue-200 transition-colors">
              Terms of Service
            </Link>{" "}
            and{" "}
            <Link href="/privacy" className="text-blue-300 hover:text-blue-200 transition-colors">
              Privacy Policy
            </Link>
          </div>
        </div>

        {/* Submit Button */}
        <button
          type="submit"
          disabled={isLoading || !allRequirementsMet || !passwordsMatch}
          className="w-full bg-gradient-to-r from-blue-600 to-purple-600 text-white font-semibold py-3 px-4 rounded-xl hover:from-blue-700 hover:to-purple-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:ring-offset-transparent transition-all duration-200 transform hover:scale-105 disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none"
        >
          {isLoading ? (
            <div className="flex items-center justify-center">
              <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
              </svg>
              Creating account...
            </div>
          ) : (
            "Create Account"
          )}
        </button>

        {/* Sign In Link */}
        <div className="text-center">
          <span className="text-blue-100/60">Already have an account? </span>
          <Link 
            href="/auth/login" 
            className="text-blue-300 hover:text-blue-200 font-medium transition-colors"
          >
            Sign in
          </Link>
        </div>
      </form>
    </AuthLayout>
  );
}
