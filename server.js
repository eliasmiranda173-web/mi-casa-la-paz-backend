import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();
const app = express();

app.use(cors());
app.use(express.json());

// CONEXIÓN A MONGODB - SOLO USUARIOS
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ Conectado a MongoDB - Solo usuarios'))
  .catch((error) => console.error('❌ Error MongoDB:', error));

// ESQUEMA SOLO PARA USUARIOS
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// RUTAS - SOLO USUARIOS
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'Backend funcionando - Solo usuarios en MongoDB',
    storage: 'Productos en Cloudinary' 
  });
});
// REGISTRO DE USUARIO
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    console.log('📝 Registrando usuario:', email);

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'El usuario ya existe' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hashedPassword });
    await user.save();

    console.log('✅ Usuario guardado en MongoDB:', user._id);

    const token = jwt.sign(
      { id: user._id, name: user.name, email: user.email },
      process.env.JWT_SECRET || 'mi-secreto-temporal',
      { expiresIn: '7d' }
    );

    res.status(201).json({
      token,
      user: { id: user._id, name: user.name, email: user.email }
    });

  } catch (error) {
    console.error('❌ Error registrando usuario:', error);
    res.status(500).json({ error: error.message });
  }
});

// LOGIN DE USUARIO
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    console.log('🔐 Login usuario:', email);

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: 'Usuario no encontrado' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: 'Contraseña incorrecta' });
    }

    const token = jwt.sign(
      { id: user._id, name: user.name, email: user.email },
      process.env.JWT_SECRET || 'mi-secreto-temporal',
      { expiresIn: '7d' }
    );

    console.log('✅ Login exitoso:', user.name);

    res.json({
      token,
      user: { id: user._id, name: user.name, email: user.email }
    });

  } catch (error) {
    console.error('❌ Error en login:', error);
    res.status(500).json({ error: error.message });
  }
});

// ==================== CLOUDINARY ENDPOINTS SEGUROS ====================

// Endpoint seguro para obtener productos de Cloudinary
app.get('/api/cloudinary/products', async (req, res) => {
  try {
    console.log('🔄 Backend fetching productos desde Cloudinary...');
    
    // ⚠️ FILTRO ELIMINADO: &prefix=products/
    // Ahora cargará TODAS las imágenes de Cloudinary
    const cloudinaryUrl = `https://api.cloudinary.com/v1_1/${process.env.CLOUDINARY_CLOUD_NAME}/resources/image?max_results=100&context=true`;
    
    const response = await fetch(cloudinaryUrl, {
      headers: {
        'Authorization': `Basic ${Buffer.from(process.env.CLOUDINARY_API_KEY + ':' + process.env.CLOUDINARY_API_SECRET).toString('base64')}`
      }
    });
    
    const data = await response.json();
    console.log(`✅ Backend obtuvo ${data.resources?.length || 0} productos de Cloudinary`);
    res.json(data);
  } catch (error) {
    console.error('❌ Error backend fetching Cloudinary:', error);
    res.status(500).json({ error: 'Error al cargar productos' });
  }
});
const PORT = process.env.PORT || 3002;
app.listen(PORT, () => {
  console.log(`🚀 Servidor usuarios en: http://localhost:${PORT}`);
  console.log('📊 Almacenamiento:');
  console.log('   👥 Usuarios → MongoDB (25MB)');
  console.log('   🛍️ Productos → Cloudinary (25GB GRATIS)');
});




