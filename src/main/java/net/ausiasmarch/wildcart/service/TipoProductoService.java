package net.ausiasmarch.wildcart.service;

import java.util.ArrayList;
import java.util.List;
import net.ausiasmarch.wildcart.exception.ResourceNotFoundException;
import net.ausiasmarch.wildcart.exception.ResourceNotModifiedException;
import net.ausiasmarch.wildcart.entity.TipoproductoEntity;
import net.ausiasmarch.wildcart.helper.RandomHelper;
import net.ausiasmarch.wildcart.helper.ValidationHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import net.ausiasmarch.wildcart.repository.TipoproductoRepository;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@Service
public class TipoProductoService {

    @Autowired
    TipoproductoRepository oTipoproductoRepository;

    @Autowired
    AuthService oAuthService;

    private final String[] TIPO = {"Productos", "Artículos", "Utilidades", "Herramientas", "Manufacturas", "Elaboraciones", "Mercancías"};
    private final String[] CARATERISTICA = {"artesanos", "de lujo", "económicos", "de segunda mano", "estándar", "retro", "plegables", "abatibles", "de gran tonelage", "ortopédicos", "de alta resistencia"};
    private final String[] UTILIDAD = {"para el hogar", "para el jardin", "para la restauracion", "para la oficina", "para el camping", "para colegios", "para prisiones", "para hospitales", "para cines y teatros"};

    public void validate(Long id) {
        if (!oTipoproductoRepository.existsById(id)) {
            throw new ResourceNotFoundException("id " + id + " not exist");
        }
    }

    public void validate(TipoproductoEntity oTipoproductoEntity) {
        ValidationHelper.validateStringLength(oTipoproductoEntity.getNombre(), 2, 100, "campo nombre Tipoproducto (el campo debe tener longitud de 2 a 100 caracteres)");
    }

    public TipoproductoEntity get(@PathVariable(value = "id") Long id) {
        if (oTipoproductoRepository.existsById(id)) {
            return oTipoproductoRepository.getById(id);
        } else {
            throw new ResourceNotFoundException("id " + id + " not exist");
        }
    }

    public Long count() {
        return oTipoproductoRepository.count();
    }

    public Page<TipoproductoEntity> getPage(Pageable oPageable, String strFilter) {
        Page<TipoproductoEntity> oPage = null;
        if (strFilter == null || strFilter.isEmpty() || strFilter.trim().isEmpty()) {
            oPage = oTipoproductoRepository.findAll(oPageable);
        } else {
            oPage = oTipoproductoRepository.findByNombreIgnoreCaseContaining(strFilter, oPageable);
        }
        return oPage;
    }

    @PostMapping("/")
    public Long create(@RequestBody TipoproductoEntity oTipoProductoEntity) {
        oAuthService.OnlyAdmins();
        validate(oTipoProductoEntity);
        oTipoProductoEntity.setId(null);
        return oTipoproductoRepository.save(oTipoProductoEntity).getId();
    }

    public Long update(Long id, TipoproductoEntity oTipoproductoEntity) {
        oAuthService.OnlyAdmins();
        oTipoproductoEntity.setId(id);
        validate(id);
        validate(oTipoproductoEntity);
        if (oTipoproductoRepository.existsById(id)) {
            return oTipoproductoRepository.save(oTipoproductoEntity).getId();
        } else {
            throw new ResourceNotFoundException("id not found");
        }
    }

    public Long delete(@PathVariable(value = "id") Long id) {
        oAuthService.OnlyAdmins();
        if (oTipoproductoRepository.existsById(id)) {
            oTipoproductoRepository.deleteById(id);
            if (oTipoproductoRepository.existsById(id)) {
                throw new ResourceNotModifiedException("Can't remove register " + id);
            } else {
                return id;
            }
        } else {
            return 0L;
        }
    }

    public TipoproductoEntity generate() {
        String nombre = TIPO[RandomHelper.getRandomInt(0, TIPO.length - 1)] + " " + CARATERISTICA[RandomHelper.getRandomInt(0, CARATERISTICA.length - 1)] + " " + UTILIDAD[RandomHelper.getRandomInt(0, UTILIDAD.length - 1)];
        TipoproductoEntity oTipoProductoEntity = new TipoproductoEntity();
        oTipoProductoEntity.setNombre(nombre);
        return oTipoProductoEntity;
    }

    public Long generateSome(@PathVariable(value = "amount") int amount) {
        oAuthService.OnlyAdmins();
        for (int i = 0; i < amount; i++) {
            TipoproductoEntity oTipoProductoEntity = generate();
            oTipoproductoRepository.save(oTipoProductoEntity);
        }
        return oTipoproductoRepository.count();
    }

    public TipoproductoEntity getOneRandom() {
        TipoproductoEntity oTipoProductoEntity = null;
        int iPosicion = RandomHelper.getRandomInt(0, (int) oTipoproductoRepository.count() - 1);
        Pageable oPageable = PageRequest.of(iPosicion, 1);
        Page<TipoproductoEntity> tipoProductoPage = oTipoproductoRepository.findAll(oPageable);
        List<TipoproductoEntity> tipoProductoList = tipoProductoPage.getContent();
        oTipoProductoEntity = oTipoproductoRepository.getById(tipoProductoList.get(0).getId());
        return oTipoProductoEntity;
    }

    private TipoproductoEntity generateTipoProducto(int i, int j, int k) {
        String nombre = TIPO[i] + " " + CARATERISTICA[j] + " " + UTILIDAD[k];
        TipoproductoEntity oTipoProductoEntity = new TipoproductoEntity();
        oTipoProductoEntity.setNombre(nombre);
        return oTipoProductoEntity;
    }

    private List<TipoproductoEntity> generateAllTipoProductoList() {
        List<TipoproductoEntity> TipoProdList = new ArrayList<>();
        for (int i = 0; i < TIPO.length; i++) {
            for (int j = 0; j < CARATERISTICA.length; j++) {
                for (int k = 0; k < UTILIDAD.length; k++) {
                    TipoProdList.add(this.generateTipoProducto(i, j, k));
                }
            }
        }
        return TipoProdList;
    }

    public Long generateAll() {
        oAuthService.OnlyAdmins();
        List<TipoproductoEntity> ListaTipoProd = generateAllTipoProductoList();
        for (int i = 0; i < ListaTipoProd.size(); i++) {
            oTipoproductoRepository.save(ListaTipoProd.get(i));
        }
        return oTipoproductoRepository.count();
    }

}
