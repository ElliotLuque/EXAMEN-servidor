package net.ausiasmarch.wildcart.service;

import java.time.LocalDateTime;
import java.util.List;
import javax.transaction.Transactional;
import net.ausiasmarch.wildcart.exception.UnauthorizedException;
import net.ausiasmarch.wildcart.entity.CarritoEntity;
import net.ausiasmarch.wildcart.entity.CompraEntity;
import net.ausiasmarch.wildcart.entity.FacturaEntity;
import net.ausiasmarch.wildcart.entity.ProductoEntity;
import net.ausiasmarch.wildcart.entity.UsuarioEntity;
import net.ausiasmarch.wildcart.exception.CannotPerformOperationException;
import net.ausiasmarch.wildcart.exception.ResourceNotFoundException;
import net.ausiasmarch.wildcart.helper.RandomHelper;
import net.ausiasmarch.wildcart.helper.ValidationHelper;
import net.ausiasmarch.wildcart.repository.CarritoRepository;
import net.ausiasmarch.wildcart.repository.CompraRepository;
import net.ausiasmarch.wildcart.repository.FacturaRepository;
import net.ausiasmarch.wildcart.repository.ProductoRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import net.ausiasmarch.wildcart.repository.UsuarioRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

@Service
public class CarritoService {

    @Autowired
    UsuarioRepository oUsuarioRepository;

    @Autowired
    ProductoService oProductoService;

    @Autowired
    UsuarioService oUsuarioService;

    @Autowired
    FacturaRepository oFacturaRepository;

    @Autowired
    CarritoRepository oCarritoRepository;

    @Autowired
    CompraRepository oCompraRepository;

    @Autowired
    ProductoRepository oProductoRepository;

    @Autowired
    AuthService oAuthService;

    public void validate(Long id) {
        if (!oCarritoRepository.existsById(id)) {
            throw new ResourceNotFoundException("id " + id + " not exist");
        }
    }

    public void validate(CarritoEntity oCarritoEntity) {
        ValidationHelper.validateRange(oCarritoEntity.getCantidad(), 1, 1000, "campo cantidad de la entidad carrito (debe ser un entero entre 1 y 1000)");
        //el precio sale de la bd: se copia del precio del producto, se supone que está validado. Este campo se borrará porque el precio se fija en la compra!!!
        ValidationHelper.validateRange(oCarritoEntity.getPrecio(), 1, 1000, "campo cantidad de la entidad carrito (debe ser un entero entre 0 y 1000000)");
        oUsuarioService.validate(oCarritoEntity.getUsuario().getId());
        oProductoService.validate(oCarritoEntity.getProducto().getId());
    }

// admins services
    public CarritoEntity get(Long id) {
        validate(id);
        return oCarritoRepository.getById(id);
    }

    public Long count() {
        oAuthService.OnlyAdmins();
        return oCarritoRepository.count();
    }

    public Page<CarritoEntity> getPage(Pageable oPageable, Long lUsuario, Long lProducto) {
        oAuthService.OnlyAdminsOrUsers();
        Page<CarritoEntity> oPage = null;
        if (oAuthService.isAdmin()) {
            if (lUsuario != null) {
                oPage = oCarritoRepository.findByUsuarioId(lUsuario, oPageable);
            } else if (lProducto != null) {
                oPage = oCarritoRepository.findByProductoId(lProducto, oPageable);
            } else {
                oPage = oCarritoRepository.findAll(oPageable);
            }
        } else {
            oPage = oCarritoRepository.findByUsuarioId(oAuthService.getUserID(), oPageable);
        }
        return oPage;
    }

    public Long create(CarritoEntity oCarritoEntity) {
        oAuthService.OnlyAdmins(); //users must use add option
        validate(oCarritoEntity);
        oCarritoEntity.setId(null);
        return oCarritoRepository.save(oCarritoEntity).getId();
    }

    public Long update(CarritoEntity oCarritoEntity) {
        oAuthService.OnlyAdmins();
        validate(oCarritoEntity.getId());
        validate(oCarritoEntity);
        return oCarritoRepository.save(oCarritoEntity).getId();
    }

    public Long delete(Long id) {
        validate(id);
        oAuthService.OnlyAdminsOrOwnUsersData(oCarritoRepository.getById(id).getUsuario().getId());
        oCarritoRepository.deleteById(id);
        return id;
    }

    public Long generate(Long amount) {
        oAuthService.OnlyAdmins();
        for (int i = 0; i < amount; i++) {
            CarritoEntity oCarrito = new CarritoEntity();
            oCarrito.setUsuario(oUsuarioService.getOneRandom());
            oCarrito.setProducto(oProductoService.getOneRandom());
            oCarrito.setCantidad(RandomHelper.getRandomInt(1, 10));
        }
        return count();
    }

// users services
    @Transactional
    public Long add(Long id_producto, int amount) {
        oAuthService.OnlyUsers();
        ProductoEntity oProducto = oProductoService.get(id_producto);
        oProductoService.validate(oProducto.getId());
        if (amount > 0 && amount <= 1000) {
            if (oCarritoRepository.countByUsuarioIdAndProductoId(oAuthService.getUserID(), oProducto.getId()) == 0) {
                CarritoEntity oCarritoEntity = new CarritoEntity();
                oCarritoEntity.setId(null);
                oCarritoEntity.setProducto(oProductoService.get(oProducto.getId()));
                oCarritoEntity.setUsuario(oUsuarioService.get(oAuthService.getUserID()));
                oCarritoEntity.setCantidad(amount);
                oCarritoRepository.save(oCarritoEntity);
            } else {
                List<CarritoEntity> oCarritoEntityList = oCarritoRepository.findByUsuarioIdAndProductoId(oAuthService.getUserID(), oProducto.getId());
                if (oCarritoEntityList.size() == 1) {
                    CarritoEntity oCarritoEntity = oCarritoEntityList.get(0);
                    oCarritoEntity.setCantidad(oCarritoEntity.getCantidad() + amount);
                    oCarritoRepository.save(oCarritoEntity);
                } else {
                    Long sum = 0L;
                    for (int i = 0; i < oCarritoEntityList.size(); i++) {
                        sum = sum + oCarritoEntityList.get(i).getCantidad();
                    }
                    oCarritoRepository.deleteByUsuarioIdAndProductoId(oAuthService.getUserID(), oProducto.getId());
                    CarritoEntity oCarritoEntity = new CarritoEntity();
                    oCarritoEntity.setId(null);
                    oCarritoEntity.setProducto(oProductoService.get(oProducto.getId()));
                    oCarritoEntity.setUsuario(oUsuarioService.get(oAuthService.getUserID()));
                    oCarritoEntity.setCantidad((int) (sum + amount));
                    oCarritoRepository.save(oCarritoEntity);
                }
            }
        } else {
            throw new CannotPerformOperationException("amount must be between 1 and 1000");
        }
        return oCarritoRepository.countByUsuarioId(oAuthService.getUserID());
    }

    @Transactional
    public Long reduce(Long id_producto, int amount) {
        oAuthService.OnlyUsers();
        ProductoEntity oProducto = oProductoService.get(id_producto);
        oProductoService.validate(oProducto.getId());
        if (amount > 0 && amount <= 1000) {
            if (oCarritoRepository.countByUsuarioIdAndProductoId(oAuthService.getUserID(), oProducto.getId()) == 0) {
                throw new CannotPerformOperationException("no exist that product in users cart");
            } else {
                List<CarritoEntity> oCarritoEntityList = oCarritoRepository.findByUsuarioIdAndProductoId(oAuthService.getUserID(), oProducto.getId());
                if (oCarritoEntityList.size() == 1) {
                    CarritoEntity oCarritoEntity = oCarritoEntityList.get(0);
                    if (oCarritoEntity.getCantidad() - amount < 0) {
                        oCarritoEntity.setCantidad(0);
                    } else {
                        oCarritoEntity.setCantidad(oCarritoEntity.getCantidad() - amount);
                    }
                    oCarritoRepository.save(oCarritoEntity);
                } else {
                    Long sum = 0L;
                    for (int i = 0; i < oCarritoEntityList.size(); i++) {
                        sum = sum + oCarritoEntityList.get(i).getCantidad();
                    }
                    oCarritoRepository.deleteByUsuarioIdAndProductoId(oAuthService.getUserID(), oProducto.getId());
                    CarritoEntity oCarritoEntity = new CarritoEntity();
                    oCarritoEntity.setId(null);
                    oCarritoEntity.setProducto(oProductoService.get(oProducto.getId()));
                    oCarritoEntity.setUsuario(oUsuarioService.get(oAuthService.getUserID()));
                    if (oCarritoEntity.getCantidad() - amount < 0) {
                        oCarritoEntity.setCantidad(0);
                    } else {
                        oCarritoEntity.setCantidad(oCarritoEntity.getCantidad() - amount);
                    }
                    oCarritoRepository.save(oCarritoEntity);
                }
            }
        } else {
            throw new CannotPerformOperationException("amount must be between 1 and 1000");
        }
        return oCarritoRepository.countByUsuarioId(oAuthService.getUserID());
    }

    @Transactional
    public Long empty() {
        oAuthService.OnlyUsers();
        if (oCarritoRepository.countByUsuarioId(oAuthService.getUserID()) > 0) {
            oCarritoRepository.deleteByUsuarioId(oAuthService.getUserID());
        }
        return oCarritoRepository.countByUsuarioId(oAuthService.getUserID());
    }

    @Transactional
    public Long purchase() throws CannotPerformOperationException, UnauthorizedException {
        oAuthService.OnlyUsers();
        List<CarritoEntity> oCarritoList = oCarritoRepository.findByUsuarioId(oAuthService.getUserID());
        if (oCarritoList.isEmpty()) {
            throw new CannotPerformOperationException("Empty cart");
        } else {
            FacturaEntity oFacturaEntity = new FacturaEntity();
            oFacturaEntity.setIva(21);
            oFacturaEntity.setFecha(LocalDateTime.now());
            oFacturaEntity.setPagado(false);
            UsuarioEntity oUsuarioEntity = new UsuarioEntity(oAuthService.getUserID());
            oFacturaEntity.setUsuario(oUsuarioEntity);
            CarritoEntity oCarritoEntity = null;
            for (int i = 0; i < oCarritoList.size(); i++) {
                oCarritoEntity = oCarritoList.get(i);
                ProductoEntity oProductoEntity = oCarritoEntity.getProducto();
                if (oProductoEntity.getExistencias() >= oCarritoEntity.getCantidad()) {
                    CompraEntity oCompraEntity = new CompraEntity();
                    oCompraEntity.setCantidad(oCarritoEntity.getCantidad());
                    oCompraEntity.setDescuento_producto(oCarritoEntity.getProducto().getDescuento());
                    oCompraEntity.setDescuento_usuario(oCarritoEntity.getUsuario().getDescuento());
                    oCompraEntity.setFactura(oFacturaEntity);
                    oCompraEntity.setFecha(oFacturaEntity.getFecha());
                    oCompraEntity.setPrecio(oCarritoEntity.getProducto().getPrecio());
                    oCompraEntity.setProducto(oCarritoEntity.getProducto());
                    oCompraRepository.save(oCompraEntity);
                    oProductoEntity.setExistencias(oProductoEntity.getExistencias() - oCompraEntity.getCantidad());
                    oProductoRepository.save(oProductoEntity);
                } else {
                    throw new CannotPerformOperationException("No hay sufientes existencias del producto "
                            + oProductoEntity.getId() + "-" + oProductoEntity.getCodigo() + "-" + oProductoEntity.getNombre());
                }
            }
            oFacturaRepository.save(oFacturaEntity);
            oCarritoRepository.deleteByUsuarioId(oUsuarioEntity.getId());
            return ((Integer) oCarritoList.size()).longValue();
        }
    }

}
