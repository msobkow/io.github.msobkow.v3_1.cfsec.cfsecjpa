// Description: Java 25 Spring JPA Service for SecSysRoleEnables

/*
 *	server.markhome.mcf.CFSec
 *
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow
 *	
 *	Mark's Code Fractal 3.1 CFSec - Security Services
 *	
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow mark.sobkow@gmail.com
 *	
 *	These files are part of Mark's Code Fractal CFSec.
 *	
 *	Licensed under the Apache License, Version 2.0 (the "License");
 *	you may not use this file except in compliance with the License.
 *	You may obtain a copy of the License at
 *	
 *	http://www.apache.org/licenses/LICENSE-2.0
 *	
 *	Unless required by applicable law or agreed to in writing, software
 *	distributed under the License is distributed on an "AS IS" BASIS,
 *	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *	See the License for the specific language governing permissions and
 *	limitations under the License.
 *	
 */

package server.markhome.mcf.v3_1.cfsec.cfsec.jpa;

import java.io.Serializable;
import java.math.*;
import java.time.*;
import java.util.*;
import jakarta.persistence.*;
import server.markhome.mcf.v3_1.cflib.*;
import server.markhome.mcf.v3_1.cflib.dbutil.*;
import server.markhome.mcf.v3_1.cflib.keyhash.*;
import server.markhome.mcf.v3_1.cflib.xml.CFLibXmlUtil;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.text.StringEscapeUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import server.markhome.mcf.v3_1.cfsec.cfsec.*;

/**
 *	Service for the CFSecSecSysRoleEnables entities defined in server.markhome.mcf.v3_1.cfsec.cfsec.jpa
 *	using the CFSecSecSysRoleEnablesRepository to access them.
 */
@Service("cfsec31JpaSecSysRoleEnablesService")
public class CFSecJpaSecSysRoleEnablesService {

	@Autowired
	@Qualifier("cfsec31EntityManagerFactory")
	private LocalContainerEntityManagerFactoryBean cfsec31EntityManagerFactory;

	@Autowired
	private CFSecJpaSecSysRoleEnablesRepository cfsec31SecSysRoleEnablesRepository;

	/**
	 *	Create an entity, generating any database keys required along the way.
	 *
	 *		@param	data	The entity to be instantiated; must be a specific instance of CFSecJpaSecSysRoleEnables, not a subclass.
	 *
	 *		@return The updated/created entity.
	 */
	@Transactional(propagation = Propagation.REQUIRED,rollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecSysRoleEnables create(CFSecJpaSecSysRoleEnables data) {
		final String S_ProcName = "create";
		if (data == null) {
			return( null );
		}
		if (data.getRequiredContainerSysRole() == null) {
			throw new CFLibUnresolvedRelationException(getClass(),
				S_ProcName,
				"Container",
				"Container",
				"data.requiredContainerSysRole",
				"data.requiredContainerSysRole",
				"SecSysRole",
				"SecSysRole",
				null);
		}
		if (data.getRequiredParentEnableGroup() == null) {
			throw new CFLibUnresolvedRelationException(getClass(),
				S_ProcName,
				"Parent",
				"Parent",
				"data.requiredParentEnableGroup",
				"data.requiredParentEnableGroup",
				"SecSysGrp",
				"SecSysGrp",
				null);
		}
		try {
			if(data.getPKey() != null && cfsec31SecSysRoleEnablesRepository.existsById((CFSecJpaSecSysRoleEnablesPKey)data.getPKey())) {
				return( (CFSecJpaSecSysRoleEnables)(cfsec31SecSysRoleEnablesRepository.findById((CFSecJpaSecSysRoleEnablesPKey)(data.getPKey())).get()));
			}
			if (data.getRequiredRevision() <= 0) {
				data.setRequiredRevision(1);
			}
			LocalDateTime now = LocalDateTime.now();
			data.setCreatedAt(now);
			data.setUpdatedAt(now);
			return cfsec31SecSysRoleEnablesRepository.save(data);
		}
		catch(Exception ex) {
			throw new CFLibDbException(getClass(),
				S_ProcName,
				ex);
		}
	}

	/**
	 *	Update an existing entity.
	 *
	 *		@param	data	The entity to be updated.
	 *
	 *		@return The updated entity.
	 */
	@Transactional(propagation = Propagation.REQUIRED,rollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecSysRoleEnables update(CFSecJpaSecSysRoleEnables data) {
		final String S_ProcName = "update";
		if (data == null) {
			return( null );
		}
		if (data.getPKey() == null) {
			throw new CFLibNullArgumentException(getClass(),
				S_ProcName,
				0,
				"data.getPKey()");
		}
		if (data.getRequiredContainerSysRole() == null) {
			throw new CFLibUnresolvedRelationException(getClass(),
				S_ProcName,
				"Container",
				"Container",
				"data.requiredContainerSysRole",
				"data.requiredContainerSysRole",
				"SecSysRole",
				"SecSysRole",
				null);
		}
		if (data.getRequiredParentEnableGroup() == null) {
			throw new CFLibUnresolvedRelationException(getClass(),
				S_ProcName,
				"Parent",
				"Parent",
				"data.requiredParentEnableGroup",
				"data.requiredParentEnableGroup",
				"SecSysGrp",
				"SecSysGrp",
				null);
		}
		// Ensure the entity exists and that the revision matches
		CFSecJpaSecSysRoleEnables existing = cfsec31SecSysRoleEnablesRepository.findById((CFSecJpaSecSysRoleEnablesPKey)(data.getPKey()))
			.orElseThrow(() -> new CFLibCollisionDetectedException(getClass(), S_ProcName, data.getPKey()));
		if (existing.getRequiredRevision() != data.getRequiredRevision()) {
			throw new CFLibCollisionDetectedException(getClass(), S_ProcName, data.getPKey());
		}
		// Apply superior data relationships of CFSecSecSysRoleEnables to existing object
		// Apply data columns of CFSecSecSysRoleEnables to existing object
		// Update the audit columns
		data.setUpdatedAt(LocalDateTime.now());
		// Save the changes we've made
		return cfsec31SecSysRoleEnablesRepository.save(existing);
	}

	/**
	 *	Argument-based find database instance for compatibility with the current MSS code factory code base.
	 *
	 *		@param requiredSecSysRoleId
	 *		@param requiredEnableName
	 *
	 *		@return The retrieved entity, or null if no such entity exists.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecSysRoleEnables find(@Param("secSysRoleId") $implIJavaAtomType$ requiredSecSysRoleId,
		@Param("enableName") $implIJavaAtomType$ requiredEnableName) {
		return( cfsec31SecSysRoleEnablesRepository.get(requiredSecSysRoleId,
			requiredEnableName));
	}

	/**
	 *	ICFSecSecSysRoleEnablesPKey based find method for object-based access.
	 *
	 *		@param key The key of the entity to be find.
	 *
	 *		@return The entity find, or null if no such entity exists.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecSysRoleEnables find(ICFSecSecSysRoleEnablesPKey key) {
		return( cfsec31SecSysRoleEnablesRepository.get(key.getRequiredSecSysRoleId(), key.getRequiredEnableName()));
	}

	/**
	 *	Retrieve all entities from the repository
	 *
	 *		@return The list of retrieved entities, which may be empty
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecSysRoleEnables> findAll() {
		return( cfsec31SecSysRoleEnablesRepository.findAll() );
	}

	// CFSecSecSysRoleEnables specified index finders

	/**
	 *	Find zero or more entities into a List using the columns of the ICFSecSecSysRoleEnablesBySysRoleIdxKey as arguments.
	 *
	 *		@param requiredSecSysRoleId
	 *
	 *		@return List&lt;CFSecJpaSecSysRoleEnables&gt; of the found entities, or an empty list if no such entities exist.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecSysRoleEnables> findBySysRoleIdx(@Param("secSysRoleId") $implIJavaAtomType$ requiredSecSysRoleId) {
		return( cfsec31SecSysRoleEnablesRepository.findBySysRoleIdx(requiredSecSysRoleId));
	}

	/**
	 *	ICFSecSecSysRoleEnablesBySysRoleIdxKey entity list finder convenience method for object-based access.
	 *
	 *		@param key The ICFSecSecSysRoleEnablesBySysRoleIdxKey instance to use for the query arguments.
	 *
	 *		@return The found entity list, which may be empty.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecSysRoleEnables> findBySysRoleIdx(ICFSecSecSysRoleEnablesBySysRoleIdxKey key) {
		return( cfsec31SecSysRoleEnablesRepository.findBySysRoleIdx(key.getRequiredSecSysRoleId()));
	}

	/**
	 *	Find zero or more entities into a List using the columns of the ICFSecSecSysRoleEnablesByNameIdxKey as arguments.
	 *
	 *		@param requiredEnableName
	 *
	 *		@return List&lt;CFSecJpaSecSysRoleEnables&gt; of the found entities, or an empty list if no such entities exist.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecSysRoleEnables> findByNameIdx(@Param("enableName") $implIJavaAtomType$ requiredEnableName) {
		return( cfsec31SecSysRoleEnablesRepository.findByNameIdx(requiredEnableName));
	}

	/**
	 *	ICFSecSecSysRoleEnablesByNameIdxKey entity list finder convenience method for object-based access.
	 *
	 *		@param key The ICFSecSecSysRoleEnablesByNameIdxKey instance to use for the query arguments.
	 *
	 *		@return The found entity list, which may be empty.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecSysRoleEnables> findByNameIdx(ICFSecSecSysRoleEnablesByNameIdxKey key) {
		return( cfsec31SecSysRoleEnablesRepository.findByNameIdx(key.getRequiredEnableName()));
	}

	// CFSecSecSysRoleEnables specified lock-by-index methods

	/**
	 *	Argument-based lock database entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecSysRoleId
	 *		@param requiredEnableName
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecSysRoleEnables lockByIdIdx(@Param("secSysRoleId") $implIJavaAtomType$ requiredSecSysRoleId,
		@Param("enableName") $implIJavaAtomType$ requiredEnableName) {
		return( cfsec31SecSysRoleEnablesRepository.lockByIdIdx(requiredSecSysRoleId,
			requiredEnableName));
	}

	/**
	 *	ICFSecSecSysRoleEnablesPKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecSysRoleEnables lockByIdIdx(ICFSecSecSysRoleEnablesPKey key) {
		return( cfsec31SecSysRoleEnablesRepository.lockByIdIdx(key.getRequiredSecSysRoleId(), key.getRequiredEnableName()));
	}

	/**
	 *	Argument-based lock database instance for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecSysRoleId
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecSysRoleEnables> lockBySysRoleIdx(@Param("secSysRoleId") $implIJavaAtomType$ requiredSecSysRoleId) {
		return( cfsec31SecSysRoleEnablesRepository.lockBySysRoleIdx(requiredSecSysRoleId));
	}

	/**
	 *	ICFSecSecSysRoleEnablesBySysRoleIdxKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecSysRoleEnables> lockBySysRoleIdx(ICFSecSecSysRoleEnablesBySysRoleIdxKey key) {
		return( cfsec31SecSysRoleEnablesRepository.lockBySysRoleIdx(key.getRequiredSecSysRoleId()));
	}

	/**
	 *	Argument-based lock database instance for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredEnableName
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecSysRoleEnables> lockByNameIdx(@Param("enableName") $implIJavaAtomType$ requiredEnableName) {
		return( cfsec31SecSysRoleEnablesRepository.lockByNameIdx(requiredEnableName));
	}

	/**
	 *	ICFSecSecSysRoleEnablesByNameIdxKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecSysRoleEnables> lockByNameIdx(ICFSecSecSysRoleEnablesByNameIdxKey key) {
		return( cfsec31SecSysRoleEnablesRepository.lockByNameIdx(key.getRequiredEnableName()));
	}

	// CFSecSecSysRoleEnables specified delete-by-index methods

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecSysRoleId
	 *		@param requiredEnableName
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void deleteByIdIdx(@Param("secSysRoleId") $implIJavaAtomType$ requiredSecSysRoleId,
		@Param("enableName") $implIJavaAtomType$ requiredEnableName) {
		cfsec31SecSysRoleEnablesRepository.deleteByIdIdx(requiredSecSysRoleId,
			requiredEnableName);
	}

	/**
	 *	ICFSecSecSysRoleEnablesByIdIdxKey based lock method for object-based access.
	 *
	 *		@param key The ICFSecSecSysRoleEnablesByIdIdxKey of the entity to be locked.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void deleteByIdIdx(ICFSecSecSysRoleEnablesPKey key) {
		cfsec31SecSysRoleEnablesRepository.deleteByIdIdx(key.getRequiredSecSysRoleId(), key.getRequiredEnableName());
	}

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecSysRoleId
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void deleteBySysRoleIdx(@Param("secSysRoleId") $implIJavaAtomType$ requiredSecSysRoleId) {
		cfsec31SecSysRoleEnablesRepository.deleteBySysRoleIdx(requiredSecSysRoleId);
	}

	/**
	 *	ICFSecSecSysRoleEnablesBySysRoleIdxKey based lock method for object-based access.
	 *
	 *		@param key The ICFSecSecSysRoleEnablesBySysRoleIdxKey of the entity to be locked.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void deleteBySysRoleIdx(ICFSecSecSysRoleEnablesBySysRoleIdxKey key) {
		cfsec31SecSysRoleEnablesRepository.deleteBySysRoleIdx(key.getRequiredSecSysRoleId());
	}

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredEnableName
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void deleteByNameIdx(@Param("enableName") $implIJavaAtomType$ requiredEnableName) {
		cfsec31SecSysRoleEnablesRepository.deleteByNameIdx(requiredEnableName);
	}

	/**
	 *	ICFSecSecSysRoleEnablesByNameIdxKey based lock method for object-based access.
	 *
	 *		@param key The ICFSecSecSysRoleEnablesByNameIdxKey of the entity to be locked.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void deleteByNameIdx(ICFSecSecSysRoleEnablesByNameIdxKey key) {
		cfsec31SecSysRoleEnablesRepository.deleteByNameIdx(key.getRequiredEnableName());
	}

}
